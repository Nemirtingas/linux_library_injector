#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

static std::string ExpandSymlink(std::string file_path)
{
    struct stat file_stat;
    std::string link_target;
    ssize_t name_len = 128;
    while(lstat(file_path.c_str(), &file_stat) >= 0 && S_ISLNK(file_stat.st_mode) == 1)
    {
        do
        {
            name_len *= 2;
            link_target.resize(name_len);
            name_len = readlink(file_path.c_str(), &link_target[0], link_target.length());
        } while (name_len == link_target.length());
        link_target.resize(name_len);
        file_path = std::move(link_target);
    }

    return file_path;
}

class InjectorState_t
{
    std::string _LibcPath;
    size_t _DLOpenOffset;
    void* _RemoteDLOpenAddr;

    std::string _FindLibc(std::string const& libc_name)
    {
        std::string const self("/proc/self/map_files/");

        DIR* dir;
        struct dirent* dir_entry;
        std::string path;
        std::string tmp;
        size_t pos;

        dir = opendir(self.c_str());
        if (dir != nullptr)
        {
            while ((dir_entry = readdir(dir)) != nullptr)
            {
                if (dir_entry->d_type != DT_LNK)
                {// Not a link
                    continue;
                }

                tmp = ExpandSymlink(self + dir_entry->d_name);
                // At least size of libc.so
                if (tmp.length() >= (libc_name.length() + 3) && (pos = tmp.rfind('/')) != std::string::npos)
                {
                    if (tmp.find(libc_name, pos + 1) == (pos + 1))
                    {
                        if (strncmp(&tmp[tmp.length() - 3], ".so", 3) == 0 || strncmp(&tmp[libc_name.length() + pos + 1], ".so", 3) == 0)
                        {
                            path = std::move(tmp);
                            break;
                        }
                    }
                }
            }
    
            closedir(dir);
        }

        return path;
    }
    
    size_t _FindDLOpenOffset(void* addr)
    {
        Dl_info info;
        struct stat buf;
 
        if(!dladdr(addr, &info))
            return false;
 
        if(!info.dli_fbase || !info.dli_fname)
            return false;
 
        if(stat(info.dli_fname, &buf) != 0)
            return false;
 
        return (uintptr_t)addr - (uintptr_t)info.dli_fbase;
    }

    void* _FindRemoteProcessDLOpen(std::string const& pid)
    {
        std::string line;
        size_t pos;
        std::string lib_name;
        std::string remote_map("/proc/" + pid + "/maps");
        std::ifstream maps(remote_map, std::ios::binary | std::ios::in);

        if (!maps)
            return nullptr;

        while(std::getline(maps, line))
        {
            lib_name = line.substr(line.rfind(' ') + 1);
            if (lib_name == _LibcPath)
            {
                char* strend = &line[0];
                uintptr_t start = (uintptr_t)strtoul(strend, &strend, 16);
                uintptr_t end = (uintptr_t)strtoul(strend + 1, &strend, 16);
                if (start != 0 && end != 0)
                {
                    uintptr_t remote_dlopen_addr = start + _DLOpenOffset;
                    return reinterpret_cast<void*>(remote_dlopen_addr);
                }
            }
        }

        return nullptr;
    }

    void _DetachProcess(uint32_t pid)
    {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }

    bool _AttachProcess(uint32_t pid)
    {
        int status;
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
            return false;

        waitpid(pid, &status, 0);

        if (!WIFSTOPPED(status) || (WSTOPSIG(status) & 0x7f) != SIGSTOP)
        {
            _DetachProcess(pid);
            return false;
        }

        if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1)
        {
            _DetachProcess(pid);
            return false;
        }

        return true;
    }

    bool _SetupForProcess(uint32_t pid)
    {
        _RemoteDLOpenAddr = _FindRemoteProcessDLOpen(std::to_string(pid));
        if (_RemoteDLOpenAddr == nullptr)
            return false;

        return true;
    }

public:
    std::string LibcPath() const
    {
        return _LibcPath;
    }

    size_t DLOpenOffset() const
    {
        return _DLOpenOffset;
    }

    void* RemoteDLOpenAddr() const
    {
        return _RemoteDLOpenAddr;
    }

    bool Init()
    {
        std::string tmp_path = _FindLibc("libc");

        if (tmp_path.empty())
            return false;

        void* hModule = dlopen(tmp_path.c_str(), RTLD_NOW);
        void* libc_dlopen = nullptr;

        for (auto sym_name : { "__libc_dlopen_mode", "dlopen" })
        {
            if ((libc_dlopen = dlsym(hModule, sym_name)) != nullptr)
                break;
        }

        if (libc_dlopen == nullptr)
            return false;

        _DLOpenOffset = _FindDLOpenOffset(libc_dlopen);

        dlclose(hModule);
        if (_DLOpenOffset == 0)
            return false;

        _LibcPath = std::move(tmp_path);
        
        return true;
    }

    void* RemoteLoadLibrary(uint32_t pid, std::string const& libpath)
    {
        struct user_regs_struct saved_regs, work_regs;
        uint32_t saved_code;
        uintptr_t library_name_addr;
        std::string library_name_buffer(libpath);
        int status;
        void* library_handle = nullptr;

        if (!_SetupForProcess(pid))
            return nullptr;

        if (!_AttachProcess(pid))
            return nullptr;

        if (ptrace(PTRACE_GETREGS, pid, NULL, &work_regs) == -1)
        {
            _DetachProcess(pid);
            return nullptr;
        }

        saved_regs = work_regs;

        // This never fails ?
        saved_code = ptrace(PTRACE_PEEKDATA, pid, (void*)work_regs.eip, nullptr);

        library_name_buffer += '\0';
        while (library_name_buffer.size() % 4)
        {// Pad for stack
            library_name_buffer += '\0';
        }

        library_name_addr = work_regs.esp - library_name_buffer.size();

        work_regs.orig_eax = -1;
        work_regs.esp = library_name_addr - 12;
        work_regs.eip = (uintptr_t)_RemoteDLOpenAddr;
        if (ptrace(PTRACE_SETREGS, pid, 0, &work_regs) == -1)
        {
            _DetachProcess(pid);
            return nullptr;
        }

        // This never fails ?
        ptrace(PTRACE_POKEDATA, pid, (void*)saved_regs.eip, 0xcccccccc); // int 3

        ptrace(PTRACE_POKEDATA, pid, (void*)(library_name_addr - 12), saved_regs.eip);   // return address
        ptrace(PTRACE_POKEDATA, pid, (void*)(library_name_addr - 8), library_name_addr); // library_path
        ptrace(PTRACE_POKEDATA, pid, (void*)(library_name_addr - 4), 2);                 // RTLD_NOW

        for(int i = 0; i < library_name_buffer.size()/4; ++i)
        {
            ptrace(PTRACE_POKEDATA, pid, library_name_addr + i*4, reinterpret_cast<uint32_t*>(&library_name_buffer[0])[i]);
        }

        // Continue tracee now we've changed EIP to dlopen
        if (ptrace(PTRACE_CONT, pid, 0, SIGCONT) != -1)
        {
            // Wait for pid to change status.
            waitpid(pid, &status, 0);

            // If tracee is stopped, continue it
            while (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x7f) == SIGSTOP && ptrace(PTRACE_CONT, pid, 0, SIGCONT) != -1)
            {
                waitpid(pid, &status, 0);
            }

            //if (WIFSTOPPED(status))
            //{
            //    if (WSTOPSIG(status) != SIGTRAP)
            //    {
            //        std::cout << "Stopped on " << WSTOPSIG(status) << " instead of SIGTRAP" << std::endl;;
            //    }
            //    else
            //    {
            //        res = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            //        std::cout << "Stopped at " << (void*)regs.eip << ", dlopen returned: " << (void*)regs.eax << std::endl;
            //    }
            //}
            //else
            //{
            //    std::cout << "Failed to continue tracee" << std::endl;
            //}
        }

        if (ptrace(PTRACE_GETREGS, pid, NULL, &work_regs) != -1)
        {
            library_handle = (void*)work_regs.eax;
        }

        // Restore original code
        ptrace(PTRACE_POKEDATA, pid, (void*)saved_regs.eip, saved_code);

        // Restore the saved registers
        saved_regs.orig_eax = -1;
        if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1)
        {
            // std::cout << "Failed to restore registers" << std::endl;
        }

        _DetachProcess(pid);

        return library_handle;
    }

    void RemoteUnloadLibrary(uint32_t pid, void* library_handle)
    {
    }
};

int main(int argc, char* argv[])
{
    uint32_t pid = atoi(argv[1]);
    InjectorState_t injector;
    std::string inject_lib = "/home/nemir/projects/linux_so_injector/shared.so";

    if (injector.Init())
    {
        std::cout << "Found libc's(" << injector.LibcPath() << ") dlopen at: " << injector.DLOpenOffset() << std::endl;
        void* remote_handle;

        if ((remote_handle = injector.RemoteLoadLibrary(pid, inject_lib)) != nullptr)
        {
            std::cout << "Remote libc dlopen for pid " << pid << " at " << injector.RemoteDLOpenAddr() << std::endl;
            std::cout << "Injected library in remote process, library handle: " << remote_handle << std::endl;
        }
    }
    else
    {
        std::cout << "Failed to find libc dlopen" << std::endl;
    }

    return 0;
}
