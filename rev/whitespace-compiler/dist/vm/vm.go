package vm

import (
    "fmt"
    "strings"
    "time"
)

type VM struct {
    array       []int
    currentIdx  int
    stack       []int
    output      strings.Builder
}

func NewVM() *VM {
    return &VM{
        array:      []int{0},
        currentIdx: 0,
    }
}

func (v *VM) Execute(program string) (error, string) {
    for iter, cmd := range program {
        time.Sleep(10*time.Millisecond)
        if (iter % 100 == 0) {
            fmt.Println("Done with", iter, "instructions out of", len(program))
        }
        switch cmd {
        case ' ':
            v.array[v.currentIdx]++
        case '\t':
            v.currentIdx++
            if v.currentIdx >= len(v.array) {
                v.array = append(v.array, 0)
            }
        case '\n':
            v.stack = append(v.stack, v.array[v.currentIdx])
            v.array[v.currentIdx] = 0
        case '\u00A0':
            // v.stack = v.stack[:len(v.stack)-1]
            if (v.currentIdx > 0) {
                v.currentIdx--
            }     
        case '\r':
            if len(v.stack) == 0 {
                return fmt.Errorf("stack underflow"), ""
            }
            top := v.stack[len(v.stack)-1]
            v.array[v.currentIdx] ^= top
        case '\x0B':
            v.array = []int{0}
            v.currentIdx = 0
        }
}

    // Convert array to characters
    for _, val := range v.array {
        v.output.WriteRune(rune(val))
    }
    
    return nil, v.output.String()
}
