// Host boundary only; tests render the actual order action and React hooks.
import React from "react";
let api;
export function setAdminApi(value) { api = value; }
export function useApi() { return api; }
export function reactExtension(_target, render) { return render; }
export function AdminAction({ primaryAction, secondaryAction, children }) {
  return <section>{primaryAction}{secondaryAction}{children}</section>;
}
export function BlockStack({ children }) { return <div>{children}</div>; }
export function Banner({ title, children }) { return <section><h2>{title}</h2>{children}</section>; }
export function Text({ children }) { return <p>{children}</p>; }
export function Button(props) { return <button {...props} />; }
export function TextField(props) { return <input {...props} />; }
