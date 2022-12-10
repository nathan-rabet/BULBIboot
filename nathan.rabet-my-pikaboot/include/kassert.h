#ifndef KASSERT_H
#define KASSERT_H

/**
 * @brief Asserts that a condition is true. Else, it will crash the system.
 *
 * @param condition The condition to assert.
 */
void kassert(int condition);

/**
 * @brief Panic the system.
 *
 * @param msg The message to print.
 */
void panic(const char *msg);

#endif /* KASSERT_H */
