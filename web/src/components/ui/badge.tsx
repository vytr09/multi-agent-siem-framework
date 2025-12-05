import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
    "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
    {
        variants: {
            variant: {
                default:
                    "border-transparent bg-yellow-500/10 text-yellow-500 hover:bg-yellow-500/20 border-yellow-500/30",
                secondary:
                    "border-transparent bg-neutral-700 text-neutral-100 hover:bg-neutral-700/80",
                destructive:
                    "border-transparent bg-red-500/10 text-red-500 hover:bg-red-500/20 border-red-500/30",
                outline: "text-neutral-100 border-neutral-700",
                success: "border-transparent bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20 border-emerald-500/30",
            },
        },
        defaultVariants: {
            variant: "default",
        },
    }
)

export interface BadgeProps
    extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> { }

function Badge({ className, variant, ...props }: BadgeProps) {
    return (
        <div className={cn(badgeVariants({ variant }), className)} {...props} />
    )
}

export { Badge, badgeVariants }
