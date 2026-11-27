// Crea o sincroniza (idempotente) los usuarios de MongoDB con mínimo privilegio.
//   antfish_app      -> readWrite sobre la base de la aplicación (API en tiempo de ejecución)
//   antfish_migrator -> readWrite + dbAdmin sobre la misma base (solo init_db: collMod/índices)
// Las credenciales llegan por variables de entorno; nada se escribe en el repositorio.
const dbName = process.env.DATABASE_NAME;
const admin = db.getSiblingDB("admin");

function ensureUser(user, pwd, roles) {
  if (!user || !pwd) {
    throw new Error("Faltan credenciales para " + user);
  }
  if (admin.getUser(user)) {
    admin.updateUser(user, { pwd: pwd, roles: roles });
    print("usuario actualizado: " + user);
  } else {
    admin.createUser({ user: user, pwd: pwd, roles: roles });
    print("usuario creado: " + user);
  }
}

ensureUser(process.env.MONGO_APP_USER, process.env.MONGO_APP_PASSWORD, [
  { role: "readWrite", db: dbName },
]);
ensureUser(process.env.MONGO_MIGRATOR_USER, process.env.MONGO_MIGRATOR_PASSWORD, [
  { role: "readWrite", db: dbName },
  { role: "dbAdmin", db: dbName },
]);
