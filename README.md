# hasz
Fast, multithreaded hash cracking tool.

## Building and running
### Prerequisites
- [Zig](https://ziglang.org) (0.14.0)

### Commands
```
# Build
zig build

# Build and run
zig build run

# See other options
zig build --help
```

## Example usage
```
hasz bcrypt -l=rockyou-75.txt "\$2a\$12\$GZcp1ScNwZ762Vtb/6sbOOsUz1RzBuwUofk8jx9Ahv8ASi15PzL6u"
```

```
hasz md5 -l=rockyou.txt 498c9984309d201da4ad7f354b5ce5d0
```
