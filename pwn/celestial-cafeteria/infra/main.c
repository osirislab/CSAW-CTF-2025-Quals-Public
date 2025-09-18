#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_DISH 0x10

void *dishes[MAX_DISH];
int dish_types[MAX_DISH];

const int type_size_array[4] = {0x1f8, 0x178, 0x138, 0xf8};

void add_dish() {
    int slot;
    printf("Slot: ");
    if (scanf("%d", &slot) != 1 || slot < 0 || slot >= MAX_DISH || dish_types[slot] != 0) {
        puts("Invalid slot!");
        int c1;
        while ((c1 = getchar()) != '\n' && c1 != EOF);
        return;
    }
    getchar();

    int type;
    printf("Type (1. Main, 2. Side, 3. Appetizer, 4. Dessert): ");
    if (scanf("%d", &type) != 1 || type < 1 || type > 4) {
        puts("Invalid type!");
        int c2;
        while ((c2 = getchar()) != '\n' && c2 != EOF);
        return;
    }
    getchar();

    dishes[slot] = malloc(type_size_array[type - 1]);
    if (!dishes[slot]) {
        fprintf(stderr, "Error: malloc failed\n");
        exit(1);
    }
    dish_types[slot] = type;

    printf("Ingredients: ");
    read(0, dishes[slot], type_size_array[type - 1]);

    puts("Dish added successfully!");
}

void delete_dish() {
    int slot;
    printf("Slot: ");
    if (scanf("%d", &slot) != 1 || slot < 0 || slot >= MAX_DISH || dishes[slot] == NULL) {
        puts("Invalid slot!");
        int c1;
        while ((c1 = getchar()) != '\n' && c1 != EOF);
        return;
    }
    getchar();

    free(dishes[slot]);
    dish_types[slot] = 0;

    puts("Dish deleted successfully!");
}

void edit_dish() {
    int slot;
    printf("Slot: ");
    if (scanf("%d", &slot) != 1 || slot < 0 || slot >= MAX_DISH || dishes[slot] == NULL || dish_types[slot] == 0) {
        puts("Invalid slot!");
        int c1;
        while ((c1 = getchar()) != '\n' && c1 != EOF);
        return;
    }
    getchar();

    printf("Ingredients: ");
    read(0, dishes[slot], type_size_array[dish_types[slot] - 1]);

    puts("Dish edited successfully!");
}

void show_dish() {
    int slot;
    printf("Slot: ");
    if (scanf("%d", &slot) != 1 || slot < 0 || slot >= MAX_DISH || dishes[slot] == NULL || dish_types[slot] == 0) {
        puts("Invalid slot!");
        int c1;
        while ((c1 = getchar()) != '\n' && c1 != EOF);
        return;
    }
    getchar();

    puts(dishes[slot]);
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("Long-distance interstellar journey must have made you very starving!");
    puts("In Celestial Cafeteria, your can customize whatever food you want!");
    puts("Just place an order and enjoy the feast!");

    while (1) {
        printf("\n");
        puts("[1] Add a dish");
        puts("[2] Delete a dish");
        puts("[3] Edit a dish");
        puts("[4] Show a dish");
        puts("[5] Place an order");
        printf(">> ");

        int choice;
        if (scanf("%d", &choice) != 1 || choice < 1 || choice > 5) {
            puts("Invalid choice!");
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue;
        }

        switch (choice) {
            case 1:
                add_dish();
                break;
            case 2:
                delete_dish();
                break;
            case 3:
                edit_dish();
                break;
            case 4:
                show_dish();
                break;
            case 5:
                puts("Bon appétit!");
                exit(1);
        }
    }

    return 0;
}