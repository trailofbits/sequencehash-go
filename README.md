# SequenceHash and SequenceMAC for Go

This package provides the SequenceHash and SequenceMAC functions for the Go programming language. You can find more details about the SequenceHash family of functions [here](https://c2sp.org/sequencehash), but the short version is that writing to SequenceHash and SequenceMAC objects is an _atomic_ operation: writing `abcd` is _not_ the same as writing `ab` and `cd` separately.

You can use SequenceHash and SequenceMAC with nearly any underlying hash function.

# How to Use SequenceHash and SequenceMAC

## Using SequenceHash

To create an SequenceHash object:

```go
hshObj, _ := hash.New(sha256.New)
hshObj.Add([]byte("ab"))
hshObj.Add([]byte("cd"))
fmt.Println(hshObj.Result())
hshObj, _ = hash.New(sha256.New)
hshObj.Add([]byte("abcd"))
fmt.Println(hshObj.Result())
```

Note that the outputs are different:

```
[219 151 40 131 168 105 217 79 108 157 237 117 19 248 62 27 94 139 108 87 153 104 89 170 166 28 202 200 56 109 101 108]
[18 113 65 89 228 94 40 101 249 20 209 186 105 67 125 39 19 117 221 128 40 205 81 3 101 197 70 248 246 210 209 22]
```

You can add domain separation strings if you'll be hashing the same inputs to be  used for separate purposes:

```go
hshObj1 := hash.New(sha256.New)
hshObj1.Add([]byte('abcd'))
fmt.Println(hshObj1.ResultWithCustomizer([]byte("customizer1")))

hshObj2 := hash.New(sha256.New)
hshObj2.Write([]byte('abcd'))
fmt.Println(hshObj2.ResultWithCustomizer([]byte("customizer2")))
```

```
[211 131 100 92 94 151 249 173 221 230 219 176 247 80 246 2 154 214 159 148 57 142 232 243 226 133 39 141 64 168 156 115]
[225 183 31 172 39 159 251 163 216 45 23 105 33 66 57 37 103 207 121 132 241 11 191 115 16 84 55 67 33 31 107 133]
```

## Using SequenceMAC

SequenceMAC works similarly to SequenceHash, though the `New` command can return an error if the key you provide is too short:

```go
key := []byte{  // key = SHA256("Give Jerry Solinas a raise")
    0x1f, 0xc7, 0x9f, 0x24, 0x45, 0x02, 0x2b, 0xbc,
    0x44, 0xcf, 0xa1, 0x40, 0xd7, 0x6e, 0x59, 0x22,
    0xaa, 0x81, 0xac, 0xe6, 0xba, 0xdd, 0xba, 0x2f,
    0x8a, 0x59, 0xac, 0xaf, 0x8b, 0x49, 0xea, 0x06}

mac1, _ := mac.New(sha256.New, key)
mac1.Add([]byte("abcd"))
fmt.Println(mac1.Result())
```

You'll get `[164 69 25 150 107 18 73 159 209 60 151 100 68 110 76 168 213 112 53 162 31 197 170 214 105 248 2 155 68 5 197 21]` as your output.

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


mac1 := mac.New(sha256.New, key1)
mac1.Add([]byte("abcd"))
fmt.Println(mac1.Result())

mac2 := mac.New(sha256.New, key2)
mac2.Add([]byte("abcd"))
fmt.Println(mac2.Result())
```

The output will be

```
[164 69 25 150 107 18 73 159 209 60 151 100 68 110 76 168 213 112 53 162 31 197 170 214 105 248 2 155 68 5 197 21]
[248 62 94 120 207 184 75 82 218 53 232 66 121 83 182 89 186 114 7 59 46 191 72 175 137 227 25 180 244 180 38 90]
```

Similarly, changing the domain separator strings will result in distinct outputs. The code

```go
key := []byte{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

mac1 := mac.New(sha256.New, key)
mac1.Add([]byte("abcd"))
fmt.Println(mac1.ResultWithCustomizer([]byte("customizer 0")))

mac2 := mac.New(sha256.New, key)
mac2.Add([]byte("abcd"))
fmt.Println(mac2.ResultWithCustomizer([]byte("customizer 1")))
```

generates the output

```
[169 65 205 61 25 176 98 184 253 37 33 156 54 101 208 245 51 80 232 211 171 184 89 238 30 178 16 0 104 125 120 7]
[225 97 172 180 234 222 85 22 200 204 18 163 122 131 240 218 165 190 196 121 24 13 129 119 231 104 179 239 39 85 164 147]
```

## A note on terminology

It's important to note that the API provided by SequenceHash is _not_ compatible with the standard `hash.Hash` API. This is not an accident.

The `Hash` interface provides the `io.Writer` interface, which deviates from the goal of SequenceHash. The `io.Writer` interface can write a partial buffer, and in I/O contexts, it's assumed that calling `Write(a)` immediately before calling `Write(b)` is the same as calling `Write` on the concatenation of `a` and `b` (barring race conditions and other oddball cases). SequenceHash behaves differently: hashing `a` and then `b` is not the same as hashing their concatenation, and there's no concept of a partial write.

To prevent confusion, we use different method names. In lieu of `Write`, we use `Add`, and instead of `Sum`, we use `Result` (or `ResultWithCustomizer`).
