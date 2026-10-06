import { useId } from 'react';
import type { ComponentProps, ReactNode } from 'react';
import { cn } from 'cn';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Textarea } from './components/ui/textarea';
import { Checkbox } from './components/ui/checkbox';
import { Select, SelectContent, SelectTrigger, SelectValue } from './components/ui/select';

type FieldLabel = { label: string; hint?: ReactNode };

export function InputField({
  label,
  hint,
  id,
  className,
  ...props
}: ComponentProps<typeof Input> & FieldLabel) {
  const generated = useId();
  const fieldId = id ?? generated;
  return (
    <div className="grid min-w-0 gap-2">
      <Label htmlFor={fieldId}>{label}</Label>
      <Input
        id={fieldId}
        aria-describedby={hint ? fieldId + '-hint' : undefined}
        className={cn('h-9', className)}
        {...props}
      />
      {hint && (
        <p id={fieldId + '-hint'} className="text-xs leading-relaxed text-muted-foreground">
          {hint}
        </p>
      )}
    </div>
  );
}

export function TextareaField({
  label,
  hint,
  id,
  className,
  ...props
}: ComponentProps<typeof Textarea> & FieldLabel) {
  const generated = useId();
  const fieldId = id ?? generated;
  return (
    <div className="grid min-w-0 gap-2">
      <Label htmlFor={fieldId}>{label}</Label>
      <Textarea
        id={fieldId}
        aria-describedby={hint ? fieldId + '-hint' : undefined}
        className={cn('min-h-24 leading-relaxed', className)}
        {...props}
      />
      {hint && (
        <p id={fieldId + '-hint'} className="text-xs leading-relaxed text-muted-foreground">
          {hint}
        </p>
      )}
    </div>
  );
}

export function SelectField({
  label,
  hint,
  id,
  children,
  placeholder,
  ...props
}: ComponentProps<typeof Select> &
  FieldLabel & { id?: string; children: ReactNode; placeholder?: string }) {
  const generated = useId();
  const fieldId = id ?? generated;
  return (
    <div className="grid min-w-0 gap-2">
      <Label htmlFor={fieldId}>{label}</Label>
      <Select {...props}>
        <SelectTrigger
          id={fieldId}
          className="h-9 w-full"
          aria-describedby={hint ? fieldId + '-hint' : undefined}
        >
          <SelectValue placeholder={placeholder} />
        </SelectTrigger>
        <SelectContent position="popper" align="start">
          {children}
        </SelectContent>
      </Select>
      {hint && (
        <p id={fieldId + '-hint'} className="text-xs leading-relaxed text-muted-foreground">
          {hint}
        </p>
      )}
    </div>
  );
}

export function CheckboxField({
  label,
  hint,
  id,
  ...props
}: ComponentProps<typeof Checkbox> & FieldLabel) {
  const generated = useId();
  const fieldId = id ?? generated;
  return (
    <div className="flex items-start gap-3 py-1">
      <Checkbox
        id={fieldId}
        aria-describedby={hint ? fieldId + '-hint' : undefined}
        className="mt-0.5"
        {...props}
      />
      <div className="grid gap-1.5">
        <Label htmlFor={fieldId} className="leading-5">
          {label}
        </Label>
        {hint && (
          <p id={fieldId + '-hint'} className="text-xs leading-relaxed text-muted-foreground">
            {hint}
          </p>
        )}
      </div>
    </div>
  );
}
