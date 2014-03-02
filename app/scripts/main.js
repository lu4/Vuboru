var sgnPem = $('[name="sgnkey1"]').val();

var key = new window.RSAKey();
key.readPrivateKeyFromPEMString(sgnPem);

var r;
var e = key.e;
var p = key.p;
var q = key.q;
var d = key.d;
var n = p.multiply(q);
var rng = new SecureRandom();
var bits = n.toString(16).length * 2;
var eBig = new BigInteger(e.toString(), 10);

do r = new BigInteger(bits, 1, rng); while (r.subtract(BigInteger.ONE).gcd(eBig).compareTo(BigInteger.ONE) != 0 || !r.isProbablePrime(10));

var r_x64 = hex2b64(r.toString(16));

$('[name="blindPrime"]').val(linebrk(r_x64, 32));
//$('[name="blindPrimeQR"]').qrcode({
//    size: 256,
//    text: m_x64,
//    render: 'div',
//    fill: 'red',
//    ecLevel: 'L'
//});

var message = new BigInteger(rstr2hex(rstr_sha512($('[name="message"]').val())), 16);

var m = message.multiply(r.modPowInt(e, n)).mod(n);
var m_x64 = hex2b64(m.toString(16));

$('[name="blindedSignature"]').val(window.linebrk(m_x64, 32));
$('[name="blindedSignatureQR"]').qrcode({
    size: 512,
    text: m_x64,
    render: 'div',
    fill: '#3a3',
    ecLevel: 'L'
});

var s = key.doPrivate(m); // Computes signature, i.e: `m^d mod n`
var s_x64 = hex2b64(s.toString(16));

$('[name="signedBlindedSignature"]').val(window.linebrk(s_x64, 32));

$('[name="signedBlindedSignatureQR"]').qrcode({
    size: 512,
    text: s_x64,
    render: 'div',
    fill: '#33a',
    ecLevel: 'L'
});

var signature = s.multiply(r.modInverse(n)).mod(n);
var signature_x64 = hex2b64(signature.toString(16));
var vote = 'Голос:\r\n' + $('[name="message"]').val() + '\r\n\r\nПідпис:\r\n' + linebrk(signature_x64, 32) + '';

$('[name="unblindedSignedBlindedSignature"]').val(vote);

$('[name="unblindedSignedBlindedSignatureQR"]').qrcode({
    size: 512,
    text: vote,
    render: 'div',
    fill: '#a33',
    ecLevel: 'L'
});

var signatureVerification = signature.modPowInt(e, n); // Computes: `signature^e mod n`

if (signatureVerification.toString() == message.toString()) {
    $('[name="signatureValidation"]').val(vote + "\r\n\r\nПідпис валідний зараховується!");
} else {
    $('[name="signatureValidation"]').val(vote + "\r\n\r\nПідпис не валідний, голос не зараховується!");
}