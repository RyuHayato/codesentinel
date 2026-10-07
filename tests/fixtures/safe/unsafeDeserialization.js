import yaml from "js-yaml";

export function loadUser(data) {
  return JSON.parse(data);
}

export function parseYaml(input) {
  return yaml.safeLoad(input);
}
