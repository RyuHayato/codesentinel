export function compute(userInput) {
  const result = eval(userInput);
  const fn = new Function("x", "return x * 2");
  setTimeout("doSomething()", 1000);
  return result ?? fn(2);
}
