#include "base64.h"

const char *b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 decode a buffer, in-place, return the length
// Only stop when the end of the buffer is reached
