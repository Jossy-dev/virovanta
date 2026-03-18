import { forwardRef } from "react";
import { cn } from "../dashboard/dashboardUtils";

const InputField = forwardRef(function InputField(
  {
    className = "",
    invalid = false,
    ...rest
  },
  ref
) {
  return (
    <input
      ref={ref}
      className={cn(
        "w-full rounded-2xl border bg-white px-4 py-3 text-sm text-slate-900 outline-none transition-all duration-200 placeholder:text-slate-400",
        "focus:border-viro-500 focus:ring-2 focus:ring-viro-200",
        "dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-viro-400 dark:focus:ring-viro-900",
        invalid
          ? "border-rose-400 focus:border-rose-500 focus:ring-rose-200 dark:border-rose-600 dark:focus:border-rose-500 dark:focus:ring-rose-900/40"
          : "border-slate-200",
        className
      )}
      aria-invalid={invalid ? "true" : "false"}
      {...rest}
    />
  );
});

export default InputField;
