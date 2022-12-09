#ifndef EMERGENCY_BOOT_H
#define EMERGENCY_BOOT_H

/**
 * @brief Emergency boot function
 * Download the firmware using the serial port (via the kermin protocol)
 * and boot it.
 *
 */
void emergency_boot(void);

#endif /* EMERGENCY_BOOT_H */
