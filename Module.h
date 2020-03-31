#pragma once

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace cr2
{

struct ModuleImpl;

class Module
{
public:
    Module();
    Module(const char *filename);
    Module(const wchar_t *filename);
    Module(FILE *fp);
    virtual ~Module();

    virtual bool is_loaded() const;
    bool load(const char *filename);
    bool load(const wchar_t *filename);
    virtual bool load(FILE *fp);
    virtual void unload();

          void *file_map(uint32_t rva = 0, uint32_t size = 1);
    const void *file_map(uint32_t rva = 0, uint32_t size = 1) const;
    uint64_t reverse_file_map(const void *ptr) const;

    template <typename T>
    T *file_map_typed(uint32_t rva = 0)
    {
        return reinterpret_cast<T *>(file_map(rva, sizeof(T)));
    }
    template <typename T>
    const T *file_map_typed(uint32_t rva = 0) const
    {
        return reinterpret_cast<const T *>(file_map(rva, sizeof(T)));
    }

    const std::string& binary() const;

    bool empty() const;
    size_t size() const;

    virtual bool get_binary(const std::string& group_name, std::string& binary) const;
    bool get_binary(const std::string& group_name, void *binary, size_t size) const;

    /////////////////////////////////////////////////////////////////////////
    // Dumping
    std::string dump(const std::string& name) const;

protected:
    std::shared_ptr<ModuleImpl> m_pimpl;
    Module(std::shared_ptr<ModuleImpl> pimpl) : m_pimpl(pimpl)
    {
    }

private:
    Module(const Module&) /* = delete */;
    Module& operator=(const Module&) /* = delete */;
};

} // namespace cr2
