import merge from "deepmerge-lib";

export function updateConfig(req, base) {
  const cfg = merge({}, req.body);
  const obj = {};
  obj[req.body.key] = req.body.value;
  const proto = obj.__proto__;
  const ctorProto = obj.constructor.prototype;
  return { cfg, proto, ctorProto };
}
