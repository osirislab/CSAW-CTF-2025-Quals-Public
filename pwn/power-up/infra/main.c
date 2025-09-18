#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#define MIN_MODULE_SIZE 0x1000
#define MAX_MODULE_SIZE 0x2000

#define MAX_MODULE 0x8

void *modules[MAX_MODULE];
int32_t module_sizes[MAX_MODULE];

int64_t energy = 0;

void create_module() {
    int index;
    printf("Index: ");
    if (scanf("%d", &index) != 1 || index < 0 || index >= MAX_MODULE || modules[index]) {
        puts("Invalid index!");
        int c1;
        while ((c1 = getchar()) != '\n' && c1 != EOF);
        return;
    }
    getchar();

    int size;
    printf("Size: ");
    if (scanf("%d", &size) != 1 || size < MIN_MODULE_SIZE || size > MAX_MODULE_SIZE) {
        puts("Invalid size!");
        int c2;
        while ((c2 = getchar()) != '\n' && c2 != EOF);
        return;
    }
    getchar();

    modules[index] = malloc(size);
    if (!modules[index]) {
        fprintf(stderr, "Error: malloc failed\n");
        exit(1);
    }

    module_sizes[index] = size;

    printf("Data: ");
    if (fgets(modules[index], module_sizes[index], stdin) == NULL) {
        fprintf(stderr, "Error: fgets failed\n");
        exit(1);
    }

    puts("Module created successfully!");
}

void delete_module() {
    int index;
    printf("Index: ");
    if (scanf("%d", &index) != 1 || index < 0 || index >= MAX_MODULE || !modules[index]) {
        puts("Invalid index!");
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        return;
    }
    getchar();

    free(modules[index]);

    puts("Module deleted successfully!");
}

void edit_module() {
    int index;
    printf("Index: ");
    if (scanf("%d", &index) != 1 || index < 0 || index >= MAX_MODULE || !modules[index]) {
        puts("Invalid index!");
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        return;
    }
    getchar();

    printf("Data: ");
    if (fgets(modules[index], module_sizes[index], stdin) == NULL) {
        fprintf(stderr, "Error: fgets failed\n");
        exit(1);
    }

    puts("Module edited successfully!");
}

void launch_starship() {
    char flag[0x80];
    memset(flag, 0, 0x80);
    int fd = open("flag.txt", O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Error: open failed\n");
        exit(1);
    }
    read(fd, flag, 0x80);
    close(fd);
    strcat(flag, "\n");
    write(1, flag, strlen(flag));
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("Your starship have been wandering for weeks in this derelict orbit, whose core is out of energy.");
    puts("You are the last engineer who must ignite the core with energy using proper modules.");
    puts("Power up the starship. Or stay stranded forever.");

    srand(time(NULL));

    while (1) {
        printf("\n");
        puts("[1] Create a module");
        puts("[2] Delete a module");
        puts("[3] Edit a module");
        puts("[4] Power up");
        puts("[5] Stay stranded");
        printf(">> ");

        int choice;
        if (scanf("%d", &choice) != 1 || choice < 1 || choice > 5) {
            puts("Invalid choice!");
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue;
        }

        int random_value = rand() % 256;

        switch (choice) {
            case 1:
                create_module();
                break;
            case 2:
                delete_module();
                break;
            case 3:
                edit_module();
                break;
            case 4:
                if (((energy >> 8) & 0xF) << 4 | ((energy >> 4) & 0xF) == random_value) {
                    puts("The core is full of energy to power up the starship!");
                    launch_starship();
                    exit(0);
                } else {
                    puts("The core is still dead as a rock without energy!");
                }
                break;
            case 5:
                puts("You and your starship will stay stranded in deep space forever!");
                exit(1);
        }
    }

    return 0;
}