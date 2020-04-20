#pragma once

#include <string>

#include <host/state.h>
#include "F00DKeyEncryptorFactory.h"

int parse_options(int argc, char* argv[], HostState &host);

int execute(const HostState &host);