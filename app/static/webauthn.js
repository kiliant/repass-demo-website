/*
 * provides interfaces to interact with webauthn and ctap2
 * using the navigator.credentials.* interfaces
 * 
 * adapted from https://github.com/Yubico/python-fido2/tree/master/examples/server/static
 */

function register_cred() {
  var myForm = document.getElementById('loginform');
  formData = new FormData(myForm);
  var username = formData.get("username");
  fetch(`/register/begin/${username}`, {
    method: 'POST',
  }).then(function (response) {
    if (response.ok) return response.arrayBuffer();
    throw new Error('Error getting registration data! User already registered?');
  }).then(CBOR.decode).then(function (options) {
    var cred = navigator.credentials.create(options);
    return cred;
  }).then(function (attestation) {
    return fetch('/register/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body: CBOR.encode({
        "attestationObject": new Uint8Array(attestation.response.attestationObject),
        "clientDataJSON": new Uint8Array(attestation.response.clientDataJSON),
      })
    });
  }).then(function (response) {
    var stat = response.ok ? 'successful' : 'unsuccessful';
  }, function (reason) {
    alert(reason);
  }).then(function () {
    window.location = '/';
  });
}

function register_recovery_cred() {
  var myForm = document.getElementById('loginform');
  formData = new FormData(myForm);
  var username = formData.get("username");
  fetch(`/enroll_recovery/begin/${username}`, {
    method: 'POST',
  }).then(function (response) {
    if (response.ok) return response.arrayBuffer();
    throw new Error('Error getting registration data! User already registered?');
  }).then(CBOR.decode).then(function (options) {
    var cred = navigator.credentials.create(options);
    return cred;
  }).then(function (attestation) {
    return fetch('/enroll_recovery/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body: CBOR.encode({
        "attestationObject": new Uint8Array(attestation.response.attestationObject),
        "clientDataJSON": new Uint8Array(attestation.response.clientDataJSON),
      })
    });
  }).then(function (response) {
    console.log(response);
    var stat = response.ok ? 'successful' : 'unsuccessful';
    window.location = response.url;
  }, function (reason) {
    alert(reason);
  });
}

function auth_cred() {
  var myForm = document.getElementById('loginform');
  formData = new FormData(myForm);
  var username = formData.get("username");

  fetch(`/authenticate/begin/${username}`, {
    method: 'POST',
  }).then(function (response) {
    if (response.ok) return response.arrayBuffer();
    throw new Error('No credential available to authenticate! Wrong user?');
  }).then(CBOR.decode).then(function (options) {
    return navigator.credentials.get(options);
  }).then(function (assertion) {
    return fetch('/authenticate/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body: CBOR.encode({
        "credentialId": new Uint8Array(assertion.rawId),
        "authenticatorData": new Uint8Array(assertion.response.authenticatorData),
        "clientDataJSON": new Uint8Array(assertion.response.clientDataJSON),
        "signature": new Uint8Array(assertion.response.signature)
      })
    })
  }).then(function (response) {
    var stat = response.ok ? 'successful' : 'unsuccessful';
  }, function (reason) {
    alert(reason);
  }).then(function () {
    window.location = '/';
  });
}

function selectChange(f) {
  fetch(`/approvals_needed/${f.value}`).then(function (response) {
    if (!response.ok) alert("Error setting approvals needed!")});
}
