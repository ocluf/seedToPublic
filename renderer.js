const calculatePublicKey = require("./generatePublicKey");

const button = document.getElementById("calculateButton");
const textArea = document.getElementById("seedInput");
const publicKeyField = document.getElementById("publicKeyField");

button.addEventListener("click", () => {
  calculatePublicKey(textArea.value).then((valueToDisplay) => {
    publicKeyField.innerText = valueToDisplay;
  });
});
