package lexer

import (
    "io/ioutil"
    "strings"
)

func CleanAndParse(filename string) (string, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return "", err
    }

    var cleaned strings.Builder
    for _, r := range string(data) {
        switch r {
        case ' ', '\t', '\n', '\u00A0', '\r', '\x0B':
            cleaned.WriteRune(r)
        }
    }
    return cleaned.String(), nil
}
