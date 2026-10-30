import * as React from 'react'
import { cn } from '@/lib/utils'

/** A styled native <select>: fully keyboard- and screen-reader-accessible, with OS-native mobile pickers. */
export const NativeSelect = React.forwardRef<HTMLSelectElement, React.ComponentProps<'select'>>(({ className, ...props }, ref) => (
  <select
    ref={ref}
    className={cn(
      'h-9 border border-input bg-card px-3 text-sm text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50',
      className,
    )}
    {...props}
  />
))
NativeSelect.displayName = 'NativeSelect'
