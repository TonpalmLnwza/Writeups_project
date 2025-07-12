# Some Assembly Required 1
The challenge link--> [picoCTF.org](https://play.picoctf.org/practice/challenge/152?page=1&search=q)

This's a part of Web exploitation from picoCTF.  

<img width="927" height="321" alt="Image" src="https://github.com/user-attachments/assets/cac49bd3-7bc2-4c83-98d6-13eff1def6ee" />

They give the link for webside--> [Webside](http://mercury.picoctf.net:37669/index.html)

---

## Problem description

This is a Web exploitation challenge that requires us to find a vulnerability in the web to access the hidden password(flag). 

---

## Problem sloving
They give us a link for go to webside, and first open the link. this's a website that requires us to enter a password(flag).

<img width="915" height="282" alt="Image" src="https://github.com/user-attachments/assets/c198dea4-6805-44bf-9ab7-c4a8913d32ed" />

We will use the view page source to view the page's source, we can see it contains 1 js file "G82XCw5CX3.js"
 
<img width="892" height="352" alt="Image" src="https://github.com/user-attachments/assets/2e21ef01-f5cd-46df-8ff6-141918cd1912" />

---
## Analyze the Java Script

When we open the js file. it's difficul to read as it stuff everything on only 1 line, so i don't have knowledge about Java script, i use chatGPT help me to reformatted it.

```js
const _0x402c = [
  'value',            // 0x1d6
  '2wfTpTR',
  'instantiate',      // 0x1d8
  '275341bEPcme',
  'innerHTML',        // 0x1da
  '1195047NznhZg',
  '1qfevql',
  'input',            // 0x1dd
  '1699808QuoWhA',
  'Correct!',         // 0x1df
  'check_flag',       // 0x1e0
  'Incorrect!',       // 0x1e1
  './JIFxzHyW8W',     // 0x1e2
  '23SMpAuA',
  '802698XOMSrr',
  'charCodeAt',       // 0x1e5
  '474547vVoGDO',
  'getElementById',   // 0x1e7
  'instance',         // 0x1e8
  'copy_char',        // 0x1e9
  '43591XxcWUl',
  '504454llVtzW',
  'arrayBuffer',      // 0x1ec
  '2NIQmVj',
  'result'            // 0x1ee
];

const _0x4e0e = function (_0x553839, _0x53c021) {
  _0x553839 = _0x553839 - 0x1d6;
  let _0x402c6f = _0x402c[_0x553839];
  return _0x402c6f;
};

(function (_0x76dd13, _0x3dfcae) {
  const _0x371ac6 = _0x4e0e;
  while (true) {
    try {
      const _0x478583 = -parseInt(_0x371ac6(0x1eb))
        + parseInt(_0x371ac6(0x1ed))
        - parseInt(_0x371ac6(0x1db)) * -parseInt(_0x371ac6(0x1d9))
        - parseInt(_0x371ac6(0x1e2)) * -parseInt(_0x371ac6(0x1e3))
        - parseInt(_0x371ac6(0x1de)) * parseInt(_0x371ac6(0x1e0))
        + parseInt(_0x371ac6(0x1d8)) * parseInt(_0x371ac6(0x1ea))
        - parseInt(_0x371ac6(0x1e5));
      if (_0x478583 === _0x3dfcae) break;
      else _0x76dd13.push(_0x76dd13.shift());
    } catch (_0x41d31a) {
      _0x76dd13.push(_0x76dd13.shift());
    }
  }
})(_0x402c, 0x994c3);

// โหลด WebAssembly module
let exports;
(async () => {
  const _ = _0x4e0e;
  let wasmFile = await fetch(_(0x1e9));
  let wasmModule = await WebAssembly[_(0x1d8)](await wasmFile[_(0x1ec)]());
  let wasmInstance = wasmModule[_(0x1e8)];
  exports = wasmInstance.exports;
})();

// เรียกใช้เมื่อกดปุ่ม
function onButtonPress() {
  const _ = _0x4e0e;

  // รับค่าจาก input
  let userInput = document[_(0x1e7)](_(0x1dd))[_(0x1d6)];

  // ส่งตัวอักษรแต่ละตัวเข้า WebAssembly
  for (let i = 0; i < userInput.length; i++) {
    exports[_(0x1e9)](userInput[_(0x1e5)](i), i);
  }

  // ส่ง null terminator เข้าไป (0x00)
  exports['copy_char'](0x0, userInput.length);

  // ตรวจสอบผลลัพธ์
  if (exports[_(0x1e0)]() == 1) {
    document[_(0x1e7)](_(0x1ee))[_(0x1da)] = _(0x1df); // Correct!
  } else {
    document[_(0x1e7)](_(0x1ee))[_(0x1da)] = _(0x1e1); // Incorrect!
  }
}
```

**ChatGPT comment how to code working on code(//)**

---

## Find the flag

We will focus on the extracted files(./JIFxzHyW8W) part, and open it.
Let's have a look at the file by changing the URL to /JIFxzHyW8W so we can download the file to our computer.

- When we open the file we will get this!!

```
asm   `  `` `  p 1Aฐ
 Aฐ
 A€
 Aฐ

 A€
 Aฐ
 A 
 A
 กmemory __wasm_call_ctors  strcmp 
check_flag input	copy_char __dso_handle
__data_end
__global_base
__heap_base
__memory_base__table_base 
๚ 
็*#€€€€ !A !  k!   6  6 (!  6 (!  6@@ (! A!   j!	  	6  -  !
  
: 
 (!
A! 
 j!
  
6 
-  !  : 
 - 
!A!  q!@ 
  - 
!A!  q! - 
!A!  q!  k!  6
 - 
!A!  q! - 
!A!  q! ! !    F!!A!" ! "q!# #
 
 - 
!$A!% $ %q!& - 
!'A!( ' (q!) & )k!*  *6
 (!+ +
L
A ! Aฐ€€ !A€€€ !  €€€ ! !  !  G!A!    s!A!	  	q!
 

?#€€€€ !A!  k!   6  6 (! (!  : ฐ€€ 

2 A€
+picoCTF{a8bae10f4d9544110222c2d639dc6de6}
```

We will see the flag is hidden on last part in the file.
"picoCTF{a8bae10f4d9544110222c2d639dc6de6}"

## Good Luck!
