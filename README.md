# ElementHash and ElementMAC for Go

This package provides the ElementHash and ElementMAC functions for the Go programming language. You can find more details about the ElementHash family of functions [here](http://www.elementhash.xyz/), but the short version is that writing to ElementHash and ElementMAC objects is an _atomic_ operation: writing `abcd` is _not_ the same as writing `ab` and `cd` separately.

You can use ElementHash and ElementMAC with nearly any underlying hash function.

# How to Use ElementHash and ElementMAC

## Using ElementHash

To create an ElementHash object:

```go
import crypto::sha256;
import elementhash::hash::ElementHash;

hshObj := ElementHash::New(sha256.New)
hshObj.Write([]byte('ab'))
hshObj.Write([]byte('cd'))
fmt.Println(hshObj.Sum())
hshObj.Reset()
hshObj.Write([]byte('abcd'))
fmt.Println(hshObj.Sum())
```

Note that the outputs are different:

```
[254, 79, 231, 169, 24, 156, 128, 90, 22, 165, 54, 40, 55, 148, 209, 104, 161, 57, 114, 33, 4, 168, 214, 172, 175, 204, 229, 105, 100, 255, 141, 133]
[128, 218, 237, 206, 161, 254, 206, 177, 233, 129, 193, 36, 139, 60, 233, 192, 62, 233, 41, 142, 223, 196, 6, 84, 247, 190, 240, 119, 198, 42, 15, 11]
```

You can add domain separation strings if you'll be hashing the same inputs to be  used for separate purposes:

```go
hshObj1 := ElementHash::NewWithSeparator(sha256.New, []byte('separator1'))
hshObj1.Write([]byte('abcd'))
fmt.Println(hshObj1.Sum())

hshObj2 := ElementHash::NewWithSeparator(sha256.New, []byte('separator2'))
hshObj2.Write([]byte('abcd'))
fmt.Println(hshObj2.Sum())
```

```
[220, 120, 253, 85, 218, 167, 137, 238, 163, 44, 139, 101, 60, 168, 190, 58, 180, 52, 77, 14, 77, 106, 89, 116, 155, 156, 133, 169, 103, 83, 64, 195]
[55, 172, 94, 52, 70, 241, 178, 13, 114, 247, 199, 230, 42, 231, 179, 171, 238, 106, 31, 45, 123, 209, 186, 167, 82, 174, 9, 85, 194, 224, 75, 54]
```

## Using ElementMAC

ElementMAC works similarly to ElementHash:

```go
key := []byte{  // key = SHA256("Give Jerry Solinas a raise")
    0x1f, 0xc7, 0x9f, 0x24, 0x45, 0x02, 0x2b, 0xbc,
    0x44, 0xcf, 0xa1, 0x40, 0xd7, 0x6e, 0x59, 0x22,
    0xaa, 0x81, 0xac, 0xe6, 0xba, 0xdd, 0xba, 0x2f,
    0x8a, 0x59, 0xac, 0xaf, 0x8b, 0x49, 0xea, 0x06}

mac1 := ElementMAC::NewWithSeparator(sha256.New, key, []byte("separator"))
mac1.Write([]byte("abcd"))
fmt.Println(mac1.Sum())
```

You'll get `e1f91ecb77153ffe0b0e2ca25d3696af4ebbdd6845ca9711ef2494867eb97765` as your output.

Obviously, different keys should give you different outputs:

```go
key1 := []byte{
    0x1f, 0xc7, 0x9f, 0x24, 0x45, 0x02, 0x2b, 0xbc,
    0x44, 0xcf, 0xa1, 0x40, 0xd7, 0x6e, 0x59, 0x22,
    0xaa, 0x81, 0xac, 0xe6, 0xba, 0xdd, 0xba, 0x2f,
    0x8a, 0x59, 0xac, 0xaf, 0x8b, 0x49, 0xea, 0x06}

key2 := []byte{
    0x65, 0x50, 0x6e, 0x9e, 0xc5, 0x4e, 0x98, 0x56,
    0x8f, 0x22, 0x88, 0xce, 0x7f, 0x9f, 0xcc, 0x41,
    0x71, 0x9e, 0xc1, 0x7e, 0x89, 0xd9, 0x5d, 0x7b,
    0x12, 0x07, 0x49, 0xa9, 0xc5, 0x70, 0x1c, 0x5a}


mac1 := ElementMAC::NewWithSeparator(sha256.New, key1, []byte("separator"))
mac1.Write([]byte("abcd"))
fmt.Println(mac1.Sum())

mac2 := ElementMAC::NewWithSeparator(sha256.New, key2, []byte("separator"))
mac2.Write([]byte("abcd"))
fmt.Println(mac2.Sum())
```

The output will be

```
e1f91ecb77153ffe0b0e2ca25d3696af4ebbdd6845ca9711ef2494867eb97765
65506e9ec54e98568f2288ce7f9fcc41719ec17e89d95d7b120749a9c5701c5a
```

## Tips

ElementHash and ElementMAC instances can be reset using the `Reset` method, which can be more efficient in the case of large keys or separators.

ElementHash and ElementMAC instances can be written to _after_ a hash is computed, allowing additional data to be incorporated into the hash. This can be useful for generating Fiat-Shamir challenges in complex ZK proofs, allowing inputs from early stages of a protocol to "carry into" later stages.