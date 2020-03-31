#include "PEModule.h"
#include "dumping.h"
#include <string>
#include <cstring>
#include <cassert>
#include "internal.h"

namespace cr2
{

Module::Module() : m_pimpl(new ModuleImpl)
{
}

Module::Module(const char *filename) : m_pimpl(new ModuleImpl)
{
    load(filename);
}

Module::Module(const wchar_t *filename) : m_pimpl(new ModuleImpl)
{
    load(filename);
}

Module::Module(FILE *fp) : m_pimpl(new ModuleImpl)
{
    load(fp);
}

Module::~Module()
{
}

bool Module::is_loaded() const
{
    return !m_pimpl->binary.empty();
}

bool Module::load(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
        return false;
    bool ret = load(fp);
    fclose(fp);
    return ret;
}

bool Module::load(const wchar_t *filename)
{
#ifdef _WIN32
    FILE *fp = _wfopen(filename, L"rb");
    if (!fp)
        return false;
    bool ret = load(fp);
    fclose(fp);
    return ret;
#else
    return false;
#endif
}

bool Module::load(FILE *fp)
{
    unload();

    char buffer[512];
    try
    {
        for (;;)
        {
            size_t size = fread(buffer, 1, sizeof(buffer), fp);
            if (!size)
                break;
            m_pimpl->binary.append(buffer, &buffer[size]);
        }
    }
    catch (std::bad_alloc&)
    {
        unload();
        return false;
    }

    return true;
}

void *Module::file_map(uint32_t rva, uint32_t size)
{
    if (m_pimpl->binary.empty() || rva + size > m_pimpl->binary.size())
        return NULL;

    return &m_pimpl->binary[rva];
}

const void *Module::file_map(uint32_t rva, uint32_t size) const
{
    if (m_pimpl->binary.empty() || rva + size > m_pimpl->binary.size())
        return NULL;

    return &m_pimpl->binary[rva];
}

uint64_t Module::reverse_file_map(const void *ptr) const
{
    const char *binary = m_pimpl->binary.c_str();
    if (binary <= ptr && ptr < binary + size())
        return reinterpret_cast<const char *>(ptr) - binary;

    return 0;
}

void Module::unload()
{
    m_pimpl->binary.clear();
}

size_t Module::size() const
{
    return m_pimpl->binary.size();
}

bool Module::empty() const
{
    return size() == 0;
}

bool Module::get_binary(const std::string& group_name, std::string& binary) const
{
    try
    {
        if (group_name == "binary")
        {
            binary.resize(size());
            std::memcpy(&binary[0], file_map(), size());
            return true;
        }
    }
    catch (std::bad_alloc&)
    {
        ;
    }

    return false;
}

const std::string& Module::binary() const
{
    return m_pimpl->binary;
}

bool Module::get_binary(const std::string& group_name, void *binary, size_t size) const
{
    std::string bin;
    if (get_binary(group_name, bin) && bin.size() == size)
    {
        std::memcpy(binary, &bin[0], size);
        return true;
    }
    return false;
}

std::string Module::dump(const std::string& name) const
{
    if (name == "binary")
    {
#if defined(_WIN64) || defined(__x86_64__) || defined(__ppc64__)
        return string_of_hex_dump64(binary().c_str(), binary().size(), 0);
#else
        return string_of_hex_dump32(binary().c_str(), binary().size(), 0);
#endif
    }
    return "";
}

} // namespace cr2