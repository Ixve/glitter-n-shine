using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace Shine
{
    public static class Bridge
    {
        public static string Run(string version)
        {
            try
            {
                Assembly asm = null;
                Type boot = null;
                foreach (Assembly a in AppDomain.CurrentDomain.GetAssemblies())
                {
                    Type t = a.GetType("Eft.Launcher.Bootstrapper", false);
                    if (t != null) { asm = a; boot = t; break; }
                }
                if (boot == null) return "ERR|bootstrapper";

                object provider = null;
                foreach (FieldInfo f in boot.GetFields(BindingFlags.Static |
                             BindingFlags.NonPublic | BindingFlags.Public))
                {
                    if (typeof(IServiceProvider).IsAssignableFrom(f.FieldType))
                    {
                        object v = f.GetValue(null);
                        if (v != null) { provider = v; break; }
                    }
                }
                if (provider == null) return "ERR|provider";

                Type settingsType = asm.GetType(
                    "Eft.Launcher.Services.SettingsService.ISettingsService", false);
                if (settingsType == null) return "ERR|settings-type";
                object settings = ((IServiceProvider)provider).GetService(settingsType);
                if (settings == null) return "ERR|settings";

                object branch = SelectedBranch(settings);
                if (branch == null) return "ERR|branch";

                object svc = Prop(branch, "GameBackendService");
                if (svc == null) svc = BackendFromFactory(asm, provider, branch);
                if (svc == null) return "ERR|backend";

                object ver = ParseVersion(asm, version);
                if (ver == null) ver = Prop(branch, "GameVersion");
                if (ver == null) return "ERR|version";

                string branchName = Prop(branch, "Name") as string;
                if (string.IsNullOrEmpty(branchName)) branchName = "live";

                MethodInfo m = svc.GetType().GetMethod("GetGameSessionAsync");
                if (m == null)
                {
                    Type bt = asm.GetType(
                        "Eft.Launcher.Services.BackendService.IGameBackendService", false);
                    if (bt != null) m = bt.GetMethod("GetGameSessionAsync");
                }
                if (m == null) return "ERR|method";

                object task = m.Invoke(svc, new object[] { ver, branchName, CancellationToken.None });
                if (task == null) return "ERR|task";
                ((Task)task).Wait();

                object info = task.GetType().GetProperty("Result").GetValue(task, null);
                if (info == null) return "ERR|info";
                string s = info.GetType().GetProperty("Session").GetValue(info, null) as string;
                if (string.IsNullOrEmpty(s)) return "ERR|empty";

                return "OK|" + s;
            }
            catch (Exception ex)
            {
                string s = "";
                for (Exception x = ex; x != null; x = x.InnerException)
                    s += x.GetType().Name + ": " + x.Message + " ";
                return "ERR|" + s;
            }
        }

        static object SelectedBranch(object settings)
        {
            object game = Prop(settings, "SelectedGame");
            if (game == null) return null;
            return Prop(game, "SelectedBranch");
        }

        static object BackendFromFactory(Assembly asm, object provider, object branch)
        {
            try
            {
                Type ft = asm.GetType(
                    "Bsg.Launcher.Services.BackendService.IGameBackendServiceFactory", false);
                if (ft == null) return null;
                object factory = ((IServiceProvider)provider).GetService(ft);
                if (factory == null) return null;
                MethodInfo create = ft.GetMethod("CreateGameBackendService");
                if (create == null) return null;
                ParameterInfo[] ps = create.GetParameters();
                object branchArg = (ps.Length == 1 &&
                    ps[0].ParameterType.IsInstanceOfType(branch)) ? branch : null;
                if (branchArg == null && ps.Length == 1) branchArg = branch;
                return create.Invoke(factory, new object[] { branchArg });
            }
            catch { return null; }
        }

        static object ParseVersion(Assembly asm, string version)
        {
            try
            {
                Type vt = asm.GetType("Eft.Launcher.BsgVersion", false);
                if (vt == null || string.IsNullOrEmpty(version)) return null;
                MethodInfo p = vt.GetMethod("Parse", BindingFlags.Public |
                    BindingFlags.Static, null, new Type[] { typeof(string) }, null);
                return p == null ? null : p.Invoke(null, new object[] { version });
            }
            catch { return null; }
        }

        static object Prop(object obj, string name)
        {
            PropertyInfo p = obj.GetType().GetProperty(name,
                BindingFlags.Public | BindingFlags.Instance);
            return p == null ? null : p.GetValue(obj, null);
        }
    }
}
