-- ============================================================================
-- MU Finance Deliverables — database schema (Supabase / Postgres)
-- Run once in Supabase → SQL Editor. Safe to re-run: it drops and rebuilds
-- the app's own objects (it does NOT touch Supabase's auth users).
-- ============================================================================
--
-- Maker / checker model
--   • A deliverable belongs to one owner (the maker).
--   • Only the owner can submit it.
--   • A submission goes to the owner's reporting manager (the checker), who
--     approves it (→ Completed) or returns it with a comment (→ Returned).
--   • Nobody can approve their own submission. The single exception is a
--     person at the top of the chain (no manager set in the app) — their
--     items can be approved by a Master, which may be themselves; the log
--     records it as self-approved.
--   • Master (Nikita) can approve, return, reassign, hold, close, reopen or
--     force-complete anything, and manage people.
--   • Admin can create/edit deliverables and manage people, but cannot approve.
--   • Every action is written to an append-only activity log.
--
-- All writes go through the functions below (security definer). The tables
-- themselves are read-only to the app, so the rules cannot be bypassed from
-- the browser.
-- ============================================================================

drop table if exists public.task_events cascade;
drop table if exists public.tasks cascade;
drop table if exists public.people cascade;

create table public.people (
  id          uuid primary key default gen_random_uuid(),
  full_name   text not null,
  email       text not null unique check (email = lower(btrim(email)) and email like '%@%'),
  manager_id  uuid references public.people(id) on delete set null,
  role        text not null default 'member' check (role in ('member','admin','master')),
  area        text,
  active      boolean not null default true,
  created_at  timestamptz not null default now(),
  check (manager_id is null or manager_id <> id)
);

create table public.tasks (
  id              bigint generated always as identity primary key,
  code            text,
  owner_id        uuid not null references public.people(id),
  title           text not null check (length(btrim(title)) > 0),
  category        text,
  priority        text check (priority in ('P0','P1','P2')),
  frequency       text not null default 'One Time'
                  check (frequency in ('One Time','Daily','Weekly','Fortnightly','Monthly','Quarterly')),
  due_day         text,
  raised_on       date,
  due_date        date,
  support         text,
  status          text not null default 'open'
                  check (status in ('open','submitted','returned','completed','on_hold','closed')),
  latest_update   text,
  next_step       text,
  source          text,
  source_ref      text,
  submitted_at    timestamptz,
  submitted_by    uuid references public.people(id),
  submission_note text,
  submission_link text,
  reviewed_at     timestamptz,
  reviewed_by     uuid references public.people(id),
  review_note     text,
  completed_on    date,
  previous_id     bigint references public.tasks(id),
  created_by      uuid references public.people(id),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
create index on public.tasks(owner_id);
create index on public.tasks(status);

create table public.task_events (
  id          bigint generated always as identity primary key,
  task_id     bigint not null references public.tasks(id) on delete cascade,
  actor_id    uuid references public.people(id),
  action      text not null,
  from_status text,
  to_status   text,
  note        text,
  link        text,
  created_at  timestamptz not null default now()
);
create index on public.task_events(task_id);

-- ---------------------------------------------------------------------------
-- Identity helpers
-- ---------------------------------------------------------------------------
create or replace function public.today_ist() returns date
language sql stable as $$ select (now() at time zone 'Asia/Kolkata')::date $$;

-- The signed-in person = the active people row whose email matches the login.
create or replace function public.me() returns uuid
language sql stable security definer set search_path = public as $$
  select p.id from public.people p
  where p.active and p.email = lower(coalesce(auth.jwt() ->> 'email', ''))
$$;

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select p.role from public.people p where p.id = public.me()
$$;

create or replace function public.is_admin() returns boolean
language sql stable as $$ select coalesce(public.my_role() in ('admin','master'), false) $$;

create or replace function public.is_master() returns boolean
language sql stable as $$ select coalesce(public.my_role() = 'master', false) $$;

-- true when `boss` sits anywhere above `person` in the reporting chain
create or replace function public.is_above(boss uuid, person uuid) returns boolean
language sql stable security definer set search_path = public as $$
  with recursive chain(id, depth) as (
    select manager_id, 1 from public.people where id = person
    union all
    select p.manager_id, c.depth + 1 from public.people p join chain c on p.id = c.id
    where c.depth < 25
  )
  select boss is not null and exists (select 1 from chain where id = boss)
$$;

create or replace function public.can_see_owner(owner uuid) returns boolean
language sql stable as $$
  select public.me() is not null
     and (owner = public.me() or public.is_admin() or public.is_above(public.me(), owner))
$$;

-- Can the signed-in person act as checker on this task right now?
create or replace function public.can_approve(t public.tasks) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare
  v_me  uuid := public.me();
  v_mgr uuid;
begin
  if v_me is null or t.status <> 'submitted' then return false; end if;
  select manager_id into v_mgr from public.people where id = t.owner_id;
  -- top of chain: a master may approve (self-approval allowed and logged)
  if v_mgr is null then return public.is_master(); end if;
  -- everyone else: never your own submission
  if t.submitted_by = v_me or t.owner_id = v_me then return false; end if;
  return v_mgr = v_me or public.is_master();
end $$;

-- May the signed-in person create / edit / hold / close tasks for this owner?
create or replace function public.can_manage_owner(owner uuid) returns boolean
language sql stable as $$
  select public.me() is not null
     and (public.is_admin() or public.is_above(public.me(), owner))
$$;

create or replace function public.log_event(p_task bigint, p_action text, p_from text, p_to text, p_note text, p_link text default null)
returns void language sql security definer set search_path = public as $$
  insert into public.task_events(task_id, actor_id, action, from_status, to_status, note, link)
  values (p_task, public.me(), p_action, p_from, p_to, nullif(btrim(p_note), ''), nullif(btrim(p_link), ''))
$$;

create or replace function public.lock_task(p_id bigint) returns public.tasks
language plpgsql security definer set search_path = public as $$
declare t public.tasks;
begin
  if public.me() is null then raise exception 'Your login is not linked to an active team member.'; end if;
  select * into t from public.tasks where id = p_id for update;
  if not found or not public.can_see_owner(t.owner_id) then raise exception 'Deliverable not found.'; end if;
  return t;
end $$;

-- ---------------------------------------------------------------------------
-- Maker actions
-- ---------------------------------------------------------------------------
create or replace function public.submit_task(p_id bigint, p_note text default null, p_link text default null)
returns public.tasks language plpgsql security definer set search_path = public as $$
declare t public.tasks; old text;
begin
  t := public.lock_task(p_id);
  old := t.status;
  if t.owner_id <> public.me() then raise exception 'Only the owner can submit this deliverable.'; end if;
  if t.status not in ('open','returned') then raise exception 'This deliverable cannot be submitted while it is %.', t.status; end if;
  update public.tasks set status = 'submitted', submitted_at = now(), submitted_by = public.me(),
         submission_note = nullif(btrim(p_note), ''), submission_link = nullif(btrim(p_link), ''),
         reviewed_at = null, reviewed_by = null, review_note = null, updated_at = now()
   where id = p_id returning * into t;
  perform public.log_event(p_id, 'submitted', old, 'submitted', p_note, p_link);
  return t;
end $$;

create or replace function public.withdraw_submission(p_id bigint)
returns public.tasks language plpgsql security definer set search_path = public as $$
declare t public.tasks;
begin
  t := public.lock_task(p_id);
  if t.owner_id <> public.me() then raise exception 'Only the owner can withdraw a submission.'; end if;
  if t.status <> 'submitted' then raise exception 'Nothing to withdraw.'; end if;
  update public.tasks set status = 'open', submitted_at = null, submitted_by = null,
         submission_note = null, submission_link = null, updated_at = now()
   where id = p_id returning * into t;
  perform public.log_event(p_id, 'withdrawn', 'submitted', 'open', null);
  return t;
end $$;

create or replace function public.add_update(p_id bigint, p_note text)
returns public.tasks language plpgsql security definer set search_path = public as $$
declare t public.tasks;
begin
  t := public.lock_task(p_id);
  if nullif(btrim(p_note), '') is null then raise exception 'Please write the update.'; end if;
  if t.owner_id <> public.me() and not public.can_manage_owner(t.owner_id) then
    raise exception 'You cannot post updates on this deliverable.';
  end if;
  update public.tasks set latest_update = btrim(p_note), updated_at = now() where id = p_id returning * into t;
  perform public.log_event(p_id, 'update', t.status, t.status, p_note);
  return t;
end $$;

-- ---------------------------------------------------------------------------
-- Checker actions
-- ---------------------------------------------------------------------------
create or replace function public.next_due(p_due date, p_freq text) returns date
language plpgsql stable as $$
declare
  step interval := case p_freq when 'Daily' then interval '1 day' when 'Weekly' then interval '7 days'
                    when 'Fortnightly' then interval '14 days' when 'Monthly' then interval '1 month'
                    when 'Quarterly' then interval '3 months' end;
  d date := coalesce(p_due, public.today_ist());
  n int := 0;
begin
  if step is null then return null; end if;
  d := (d + step)::date;
  while d <= public.today_ist() and n < 1000 loop d := (d + step)::date; n := n + 1; end loop;
  return d;
end $$;

create or replace function public.approve_task(p_id bigint, p_note text default null, p_next_cycle boolean default true)
returns public.tasks language plpgsql security definer set search_path = public as $$
declare t public.tasks; nxt public.tasks; self_ok boolean;
begin
  t := public.lock_task(p_id);
  if t.status <> 'submitted' then raise exception 'Only submitted deliverables can be approved.'; end if;
  if not public.can_approve(t) then raise exception 'You are not the approver for this deliverable.'; end if;
  self_ok := (t.owner_id = public.me());
  update public.tasks set status = 'completed', reviewed_at = now(), reviewed_by = public.me(),
         review_note = nullif(btrim(p_note), ''), completed_on = public.today_ist(), updated_at = now()
   where id = p_id returning * into t;
  perform public.log_event(p_id, case when self_ok then 'approved (self, top of chain)' else 'approved' end,
                           'submitted', 'completed', p_note);
  if p_next_cycle and t.frequency <> 'One Time' then
    insert into public.tasks(code, owner_id, title, category, priority, frequency, due_day, raised_on, due_date,
                             support, next_step, source, source_ref, previous_id, created_by)
    values (t.code, t.owner_id, t.title, t.category, t.priority, t.frequency, t.due_day, public.today_ist(),
            public.next_due(t.due_date, t.frequency), t.support, t.next_step, t.source, t.source_ref, t.id, public.me())
    returning * into nxt;
    perform public.log_event(nxt.id, 'next cycle created', null, 'open', 'Rolled over after approval of #' || t.id);
  end if;
  return t;
end $$;

create or replace function public.return_task(p_id bigint, p_note text)
returns public.tasks language plpgsql security definer set search_path = public as $$
declare t public.tasks;
begin
  t := public.lock_task(p_id);
  if t.status <> 'submitted' then raise exception 'Only submitted deliverables can be returned.'; end if;
  if not public.can_approve(t) then raise exception 'You are not the approver for this deliverable.'; end if;
  if nullif(btrim(p_note), '') is null then raise exception 'Please say what needs to change.'; end if;
  update public.tasks set status = 'returned', reviewed_at = now(), reviewed_by = public.me(),
         review_note = btrim(p_note), updated_at = now()
   where id = p_id returning * into t;
  perform public.log_event(p_id, 'returned', 'submitted', 'returned', p_note);
  return t;
end $$;

-- ---------------------------------------------------------------------------
-- Manager / admin / master actions
-- ---------------------------------------------------------------------------
-- Hold, close, reopen (managers above the owner, admins, master).
-- Force-complete without a submission: master only.
create or replace function public.set_task_status(p_id bigint, p_status text, p_note text default null)
returns public.tasks language plpgsql security definer set search_path = public as $$
declare t public.tasks; old text;
begin
  t := public.lock_task(p_id);
  old := t.status;
  if p_status not in ('open','on_hold','closed','completed') then raise exception 'Invalid status.'; end if;
  if p_status = 'completed' then
    if not public.is_master() then raise exception 'Only the Master can mark a deliverable completed directly.'; end if;
  elsif not public.can_manage_owner(t.owner_id) then
    raise exception 'You cannot change the status of this deliverable.';
  end if;
  if old = p_status then return t; end if;
  if nullif(btrim(p_note), '') is null and p_status in ('closed','completed') then
    raise exception 'Please add a note explaining why.';
  end if;
  update public.tasks set status = p_status,
         completed_on = case when p_status = 'completed' then public.today_ist() when p_status = 'open' then null else completed_on end,
         reviewed_at = case when p_status = 'completed' then now() else reviewed_at end,
         reviewed_by = case when p_status = 'completed' then public.me() else reviewed_by end,
         review_note = case when p_status = 'completed' then btrim(p_note) else review_note end,
         updated_at = now()
   where id = p_id returning * into t;
  perform public.log_event(p_id, case p_status when 'open' then 'reopened' when 'on_hold' then 'put on hold'
                                   when 'closed' then 'closed' else 'completed by master' end, old, p_status, p_note);
  return t;
end $$;

-- Create (p->>'id' empty) or edit a deliverable. Reassigning = changing owner_id.
create or replace function public.save_task(p jsonb)
returns public.tasks language plpgsql security definer set search_path = public as $$
declare t public.tasks; v_owner uuid; v_id bigint := nullif(p->>'id','')::bigint; changes text;
begin
  if public.me() is null then raise exception 'Your login is not linked to an active team member.'; end if;
  v_owner := nullif(p->>'owner_id','')::uuid;
  if v_owner is null then raise exception 'Choose an owner.'; end if;
  if not exists (select 1 from public.people where id = v_owner and active) then raise exception 'Owner not found.'; end if;
  if not public.can_manage_owner(v_owner) then raise exception 'You can only assign deliverables to people who report to you.'; end if;
  if nullif(btrim(p->>'title'), '') is null then raise exception 'Give the deliverable a title.'; end if;

  if v_id is null then
    insert into public.tasks(code, owner_id, title, category, priority, frequency, due_day, raised_on, due_date,
                             support, next_step, source, source_ref, created_by)
    values (nullif(btrim(p->>'code'),''), v_owner, btrim(p->>'title'), nullif(p->>'category',''), nullif(p->>'priority',''),
            coalesce(nullif(p->>'frequency',''),'One Time'), nullif(p->>'due_day',''),
            coalesce(nullif(p->>'raised_on','')::date, public.today_ist()), nullif(p->>'due_date','')::date,
            nullif(p->>'support',''), nullif(p->>'next_step',''), coalesce(nullif(p->>'source',''),'App'),
            nullif(p->>'source_ref',''), public.me())
    returning * into t;
    perform public.log_event(t.id, 'created', null, 'open', null);
    return t;
  end if;

  t := public.lock_task(v_id);
  if not public.can_manage_owner(t.owner_id) then raise exception 'You cannot edit this deliverable.'; end if;
  changes := concat_ws('; ',
    case when t.owner_id is distinct from v_owner then 'owner changed' end,
    case when t.due_date is distinct from nullif(p->>'due_date','')::date then
      'due ' || coalesce(to_char(t.due_date,'DD Mon'),'none') || ' → ' || coalesce(to_char(nullif(p->>'due_date','')::date,'DD Mon'),'none') end,
    case when t.title is distinct from btrim(p->>'title') then 'title edited' end,
    case when t.priority is distinct from nullif(p->>'priority','') then 'priority ' || coalesce(nullif(p->>'priority',''),'none') end);
  update public.tasks set code = nullif(btrim(p->>'code'),''), owner_id = v_owner, title = btrim(p->>'title'),
         category = nullif(p->>'category',''), priority = nullif(p->>'priority',''),
         frequency = coalesce(nullif(p->>'frequency',''),'One Time'), due_day = nullif(p->>'due_day',''),
         raised_on = nullif(p->>'raised_on','')::date, due_date = nullif(p->>'due_date','')::date,
         support = nullif(p->>'support',''), next_step = nullif(p->>'next_step',''),
         source = nullif(p->>'source',''), source_ref = nullif(p->>'source_ref',''), updated_at = now()
   where id = v_id returning * into t;
  perform public.log_event(v_id, 'edited', t.status, t.status, nullif(changes,''));
  return t;
end $$;

-- People: admin / master only.
create or replace function public.save_person(p jsonb)
returns public.people language plpgsql security definer set search_path = public as $$
declare r public.people; v_id uuid := nullif(p->>'id','')::uuid; v_mgr uuid := nullif(p->>'manager_id','')::uuid;
        v_role text := coalesce(nullif(p->>'role',''),'member');
begin
  if not public.is_admin() then raise exception 'Only admins can manage people.'; end if;
  if v_role = 'master' and not public.is_master() then raise exception 'Only the Master can grant Master rights.'; end if;
  if v_id is not null then
    select * into r from public.people where id = v_id;
    if not found then raise exception 'Person not found.'; end if;
    if r.role = 'master' and not public.is_master() then raise exception 'Only the Master can edit a Master.'; end if;
    if r.role = 'master' and (v_role <> 'master' or not coalesce((p->>'active')::boolean, true))
       and (select count(*) from public.people where role = 'master' and active) = 1 then
      raise exception 'There must always be at least one active Master.';
    end if;
    if v_mgr is not null and (v_mgr = v_id or public.is_above(v_id, v_mgr)) then
      raise exception 'That reporting line would create a loop.';
    end if;
    update public.people set full_name = btrim(p->>'full_name'), email = lower(btrim(p->>'email')),
           manager_id = v_mgr, role = v_role, area = nullif(p->>'area',''),
           active = coalesce((p->>'active')::boolean, true)
     where id = v_id returning * into r;
  else
    insert into public.people(full_name, email, manager_id, role, area)
    values (btrim(p->>'full_name'), lower(btrim(p->>'email')), v_mgr, v_role, nullif(p->>'area',''))
    returning * into r;
  end if;
  return r;
end $$;

-- ---------------------------------------------------------------------------
-- Row level security: read-only access, scoped to what each person may see.
-- ---------------------------------------------------------------------------
alter table public.people      enable row level security;
alter table public.tasks       enable row level security;
alter table public.task_events enable row level security;

create policy people_read on public.people for select to authenticated using (public.me() is not null);
create policy tasks_read  on public.tasks  for select to authenticated using (public.can_see_owner(owner_id));
create policy events_read on public.task_events for select to authenticated
  using (exists (select 1 from public.tasks t where t.id = task_id and public.can_see_owner(t.owner_id)));

revoke all on public.people, public.tasks, public.task_events from anon, authenticated;
grant select on public.people, public.tasks, public.task_events to authenticated;

-- Functions: nothing for anonymous visitors; signed-in users may call the actions.
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function
  public.today_ist(), public.me(), public.my_role(), public.is_admin(), public.is_master(),
  public.is_above(uuid, uuid), public.can_see_owner(uuid), public.can_manage_owner(uuid),
  public.can_approve(public.tasks),
  public.submit_task(bigint, text, text), public.withdraw_submission(bigint), public.add_update(bigint, text),
  public.approve_task(bigint, text, boolean), public.return_task(bigint, text),
  public.set_task_status(bigint, text, text), public.save_task(jsonb), public.save_person(jsonb)
to authenticated;
