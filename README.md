# go-abe
Implementation of cp-abe algorithm in golang as part of my bachelor's thesis

To compile it, first configure pbc library dependencies as it is stated in its documentation: https://pkg.go.dev/github.com/Nik-U/pbc

+ At the beggining setup in `in/utils` jsons of `access_policy` and `attributes` files. Example setup can be seen in the file.
+ Then paste input file to encrypt in `in/files/input_file.txt`
+ Based on the prepared files you can run following commands in terminal
    - `go run main.go setup` - generate `public_key` and `master_secret_key` in `out/utils`
    - `go run main.go keygen` - based on `attributes`, `master_secret_key` and `public_key` generate `master_secret_key` and `user_private_key` in `out/utils`
    - `go run main.go encrypt` - based on `access_policy` and `public_key,` encrypt `input_file.txt` and generate `encrypted_input.bin` in `out/files` based on it. Also generate `ciphertext` in `out/utils`
    - `go run main.go decrypt` - based on `ciphertext` and `user_private_key` decrypt `encrypted_input.bin` - if the user has sufficient priviledges then they can read the message in `decrypted_file.txt`