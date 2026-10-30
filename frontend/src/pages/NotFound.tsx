import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export default function NotFoundPage({ what = 'page' }: { what?: string }) {
  return (
    <div className="mx-auto max-w-md border p-8 text-center">
      <h1 className="text-2xl font-bold">Not found</h1>
      <p className="mt-2 text-sm text-muted-foreground">That {what} does not exist, or you do not have access to it.</p>
      <Button asChild className="mt-4"><Link to="/">Back to dashboard</Link></Button>
    </div>
  )
}
