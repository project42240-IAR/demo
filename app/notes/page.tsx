import { Suspense } from 'react';
import { createClient } from '@/utils/supabase/server';

async function NotesContent() {
  const supabase = await createClient();
  const { data: notes } = await supabase.from("notes").select();
  return <pre>{JSON.stringify(notes, null, 2)}</pre>;
}

export default function Notes() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <NotesContent />
    </Suspense>
  );
}
