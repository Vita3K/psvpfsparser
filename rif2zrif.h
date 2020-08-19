#pragma once

#include <string>
#include <vector>

std::string rif2zrif(std::wstring &drmlicpath);

std::vector<uint8_t> get_temp_klicensee(std::string &zrif);