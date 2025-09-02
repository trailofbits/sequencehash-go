# ElementHash and ElementMAC for Go

This package provides the ElementHash and ElementMAC functions for the Go programming language. You can find more details about the ElementHash family of functions [here](http://www.elementhash.xyz/), but the short version is that writing to ElementHash and ElementMAC objects is an _atomic_ operation: writing `abcd` is _not_ the same as writing `ab` and `cd` separately.

# How to Use ElementHash and ElementMAC

To create an ElementHash object:

```go
import crypto::sha256;
import elementhash::hash::ElementHash;

hshObj := ElementHash::New(sha256.New)
hshObj.Write([]byte('ab'))
hshObj.Write([]byte('cd'))
fmt.Println("{}", hshObj.Sum())
hshObj.Reset()
hshObj.Write([]byte('abcd'))
fmt.Println("{}", hshObj.Sum())
```

TODO: Fill in more.