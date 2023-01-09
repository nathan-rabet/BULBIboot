#ifndef KASSERT_H
#define KASSERT_H

#include <stdbool.h>

/**
 * @brief Asserts that a condition is true. Else, it will panic the system.
 *
 * @param condition The condition to assert.
 */
void kassert(bool condition);

/**
 * @brief Asserts that a condition is true. Else, it will panic the system.
 *
 * @param condition The condition to assert.
 * @param msg The message to print.
 */
void kassertm(bool condition, const char *msg);

/**
 * @brief Panic the system.
 *
 * @param msg The message to print.
 */
void panic(const char *msg);

#endif /* KASSERT_H */
