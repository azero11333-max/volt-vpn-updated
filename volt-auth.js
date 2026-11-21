/* VOLT V2.3 — Supabase authentication connector.
   This browser client uses only the public anon/publishable key. Database access
   must be protected by the SQL Row Level Security policies in supabase-schema.sql. */
(function () {
  let client = null;
  const config = window.VOLT_SUPABASE_CONFIG || {};
  const configured = () => !!(config.url && config.anonKey &&
    !config.url.includes("YOUR_SUPABASE") && !config.anonKey.includes("YOUR_SUPABASE"));
  function ready() {
    if (!configured()) throw new Error("VOLT online accounts are not connected yet. Finish the Supabase setup first.");
    if (!window.supabase || !window.supabase.createClient) throw new Error("The Supabase client could not load. Check your internet connection and reload VOLT.");
    if (!client) client = window.supabase.createClient(config.url, config.anonKey, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
    });
    return client;
  }
  async function syncProfile(user, displayName) {
    if (!user) return null;
    const db = ready();
    const { data: existing, error: readError } = await db.from("profiles").select("display_name").eq("id", user.id).maybeSingle();
    if (readError) throw readError;
    const name = (displayName || existing?.display_name || user.user_metadata?.display_name || user.email?.split("@")[0] || "VOLT User").slice(0, 30);
    const { error } = await db.from("profiles").upsert({ id: user.id, display_name: name, updated_at: new Date().toISOString() }, { onConflict: "id" });
    if (error) throw error;
    return { id: user.id, email: user.email, name };
  }
  window.VOLTAuth = {
    isConfigured: configured,
    async signUp(name, email, password) {
      const db = ready();
      const { data, error } = await db.auth.signUp({ email, password, options: { data: { display_name: name }, emailRedirectTo: location.href.split("#")[0] } });
      if (error) throw error;
      if (data.user && data.session) await syncProfile(data.user, name);
      return { user: data.user, needsEmailConfirmation: !!data.user && !data.session };
    },
    async signIn(email, password) {
      const db = ready();
      const { data, error } = await db.auth.signInWithPassword({ email, password });
      if (error) throw error;
      const profile = await syncProfile(data.user);
      return profile;
    },
    async updateProfile(name) {
      const db = ready();
      const { data: authData, error: authError } = await db.auth.getUser();
      if (authError) throw authError;
      if (!authData.user) throw new Error("Please log in before editing your online profile.");
      const cleanName = String(name || "").trim().slice(0, 30);
      if (cleanName.length < 2) throw new Error("Display name must be at least 2 characters.");
      const { error } = await db.from("profiles").upsert({ id: authData.user.id, display_name: cleanName, updated_at: new Date().toISOString() }, { onConflict: "id" });
      if (error) throw error;
      return { id: authData.user.id, email: authData.user.email, name: cleanName };
    },
    async resetPassword(email) {
      const db = ready();
      const { error } = await db.auth.resetPasswordForEmail(email, { redirectTo: location.href.split("#")[0] });
      if (error) throw error;
    },
    async signOut() {
      const db = ready();
      const { error } = await db.auth.signOut();
      if (error) throw error;
    },
    async currentUser() {
      const db = ready();
      const { data, error } = await db.auth.getUser();
      if (error && error.name !== "AuthSessionMissingError") throw error;
      return data?.user ? syncProfile(data.user) : null;
    },
    onChange(callback) {
      if (!configured() || !window.supabase?.createClient) return;
      const db = ready();
      return db.auth.onAuthStateChange((event, session) => {
        // Defer profile database work outside Supabase's auth callback.
        setTimeout(async () => {
          try { callback(event, session?.user ? await syncProfile(session.user) : null); }
          catch (error) { console.error("VOLT profile sync:", error); callback(event, null, error); }
        }, 0);
      });
    }
  };
})();
