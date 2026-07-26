// Encoded secret fixture — plaintext assignment lives only inside the base64
// payload after decode (base64 of password=SuperSecret123). Comments must not
// contain key=value assignment shapes that the contextual detector would match.
const payload = "cGFzc3dvcmQ9U3VwZXJTZWNyZXQxMjM=";
