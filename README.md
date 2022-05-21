# Cryptographer
[Fluent Interface](https://ko.wikipedia.org/wiki/플루언트_인터페이스)를 지향하는 암복호화 클래스입니다.
## 사용 예
```kt
val cryptographer = Cryptographer.aes(key)
  .cbc(iv)
  .pkcs5Padding()

val plainText = "plain text"
val plainBytes = plainText.toByteArray(Charsets.UTF_8)
val encryptedBytes = cryptographer.encrypt(plainBytes)
val decryptedBytes = cryptographer.decrypt(encryptedBytes)
val decryptedText = decryptedBytes.toUtf8()

assertEquals(plainText, decryptedText)
```