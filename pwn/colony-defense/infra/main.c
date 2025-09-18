#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_BUFFER_SIZE 0x8
#define ALIGNMENT_SIZE 0x10

#define MAX_WEAPON 0x10
#define MAX_WEAPON_POSITION 0x10
#define MAX_WEAPON_CAPACITY 0x500

void *weapon_position[MAX_WEAPON];
uint16_t weapon_capacity[MAX_WEAPON];

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    write(1, "Hello, colonists!\n", 18);
    write(1, "Aliens are invading your planet colony!\n", 40);
    write(1, "Actions have to be taken to defend your colony!\n", 48);
    write(1, "You can control up to 16 weapons at the same time, each with a capacity of 1280 ammo!\n", 86);

    void* colony_start = sbrk(0);
    void* colony_end = colony_start + 0x21000;

    void *weapon = NULL;
    int extra_ammo = 0;
    uint64_t weapon_level = 0;

    char position_buffer[MAX_BUFFER_SIZE] = {};
    int position;
    char capacity_buffer[MAX_BUFFER_SIZE] = {};
    int capacity;

    char choice_buffer[MAX_BUFFER_SIZE] = {};
    int choice;

    while (1) {
        write(1, "\n", 1);
        write(1, "Make a choice:\n", 15);
        write(1, "1. Build Weapon\n", 16);
        write(1, "2. Launch Weapon\n", 17);
        write(1, "3. Load Weapon\n", 15);
        write(1, "4. Check Weapon\n", 16);
        write(1, "5. Upgrade Weapon\n", 18);
        write(1, "6. Detonate Bomb\n", 17);
        write(1, ">> ", 3);

        read(0, choice_buffer, sizeof(choice_buffer)-1);
        choice = atoi(choice_buffer);

        switch (choice) {
            case 1:
                write(1, "build weapon at position: ", 26);
                read(0, position_buffer, sizeof(position_buffer)-1);
                position = atoi(position_buffer);

                if (position < 0 || position >= MAX_WEAPON_POSITION) {
                    write(1, "Invalid weapon position!\n", 25);
                    continue;
                }

                write(1, "with capacity of: ", 18);
                read(0, capacity_buffer, sizeof(capacity_buffer)-1);
                capacity = atoi(capacity_buffer);

                if (capacity < 0 || capacity > MAX_WEAPON_CAPACITY) {
                    write(1, "Invalid weapon capacity!\n", 25);
                    continue;
                }

                weapon = malloc(capacity);

                if (weapon < colony_start || weapon > colony_end) {
                    write(1, "You cannot build weapon outside of colony!\n", 43);
                    continue;
                }

                weapon_position[position] = weapon;
                weapon_capacity[position] = capacity;
                write(1, "Weapon built successfully!\n", 27);
                break;

            case 2:
                write(1, "launch weapon at position: ", 27);
                read(0, position_buffer, sizeof(position_buffer)-1);
                position = atoi(position_buffer);

                if (position < 0 || position >= MAX_WEAPON_POSITION) {
                    write(1, "Invalid weapon position!\n", 25);
                    continue;
                }

                if (weapon_position[position] == NULL) {
                    write(1, "No weapon at this position!\n", 28);
                    continue;
                }

                free(weapon_position[position]);
                write(1, "Weapon launched successfully!\n", 30);
                break;

            case 3:
                write(1, "load weapon at position: ", 25);
                read(0, position_buffer, sizeof(position_buffer)-1);
                position = atoi(position_buffer);

                if (position < 0 || position >= MAX_WEAPON_POSITION) {
                    write(1, "Invalid weapon position!\n", 25);
                    continue;
                }

                if (weapon_position[position] == NULL) {
                    write(1, "No weapon at this position!\n", 28);
                    continue;
                }

                write(1, "with ammo of: ", 14);
                read(0, weapon_position[position], weapon_capacity[position] + extra_ammo);
                write(1, "Weapon loaded successfully!\n", 28);
                break;

            case 4:
                write(1, "check weapon at position: ", 26);
                read(0, position_buffer, sizeof(position_buffer)-1);
                position = atoi(position_buffer);

                if (position < 0 || position >= MAX_WEAPON_POSITION) {
                    write(1, "Invalid weapon position!\n", 25);
                    continue;
                }

                if (weapon_position[position] == NULL) {
                    write(1, "No weapon at this position!\n", 28);
                    continue;
                }

                write(1, weapon_position[position], weapon_capacity[position] + extra_ammo);
                break;

            case 5:
                if (weapon_level != 0) {
                    write(1, "You can only upgrade weapon once!\n", 34);
                    continue;
                }

                write(1, "upgrade weapon with resource: ", 30);
                read(0, &weapon_level, sizeof(weapon_level));
                if (weapon_level == (uint64_t)main) {
                    write(1, "You upgraded weapon successfully to a lethal level with extra ammo!\n", 68);
                    extra_ammo = 8;
                } else {
                    write(1, "You have to find necessary resource to upgrade weapon!\n", 55);
                    extra_ammo = 0;
                }
                weapon_level = 0;
                break;

            case 6:
                write(1, "A suicide bomb has been activated!\n", 35);
                write(1, "Aliens were wiped out along with your colony!\n", 46);
                exit(0);

            default:
                write(1, "Noooooooo you made a bad choice!\n", 33);
                write(1, "Aliens have successfully invaded your colony!\n", 46);
                exit(1);
        }
    }

    return 0;
}