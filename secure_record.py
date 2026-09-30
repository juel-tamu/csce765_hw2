def craft_header(direction):
    version_byte = bytes(1)
    direction_byte = bytes(1)
    sequence_bytes = bytes(8)

    print(version_byte)

def seal():
    pass

def open_record():
    pass

def main():
    craft_header(1)

if __name__ == "__main__":
    main()