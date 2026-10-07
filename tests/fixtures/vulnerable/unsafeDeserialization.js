import serialize from "node-serialize";
import yaml from "js-yaml";
import vm from "vm";

export function loadUser(data) {
  return serialize.unserialize(data);
}

export function parseYaml(input) {
  return yaml.load(input);
}

export function run(code) {
  return vm.runInNewContext(code);
}
