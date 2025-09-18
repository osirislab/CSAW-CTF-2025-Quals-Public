#include <stdio.h>
#include <unistd.h>

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    char buffer[0x88] = {0};

    printf("[Commander Neil Armstrong]: The Lunar module Eagle has successfully landed at the Sea of Tranquility!\n");

    read(0, buffer, 0x10);

    printf("[Houston]: ");
    printf(buffer);
    printf("\n");

    read(0, buffer, 0x888);

    printf("[Commander Neil Armstrong]: That's one small step for man, one giant leap for mankind!\n");

    return 0;
}