#pragma once

#include <string>
#include <cstdint>
#include "ports.h"

namespace cr2
{

std::string string_of_addr32(uint32_t addr);
std::string string_of_addr64(uint64_t addr);
std::string string_of_timestamp(uint32_t timestamp);
std::string string_of_machine(uint16_t machine);
std::string string_of_file_flags(uint16_t w);
std::string string_of_section_flags(uint32_t dw);
std::string string_of_dll_flags(uint16_t w);
std::string string_of_subsystem(uint16_t w);
std::string string_formatted(const char *fmt, ...);
std::string string_of_data_directory(const void *data, uint32_t index);
std::string string_of_dos_header(const void *dos);
std::string string_of_file_header(const void *file);
std::string string_of_optional32(const void *optional);
std::string string_of_optional64(const void *optional);
std::string string_of_section_header(const void *section_header, uint32_t index);
std::string string_of_hex_dump32(const void *memory, size_t size, uint32_t base_addr);
std::string string_of_hex_dump64(const void *memory, size_t size, uint64_t base_addr);
std::string string_of_imports(const IMAGE_IMPORT_DESCRIPTOR *imports, const ImportTable& table, bool is_64bit);
std::string string_of_exports(const IMAGE_EXPORT_DIRECTORY *exports, const ExportTable& table, bool is_64bit);
std::string string_of_delay(const DelayTable& table, bool is_64bit);

} // namespace cr2
