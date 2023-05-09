#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <ldap.h>
extern "C"
{
#include <connection.h>
#include <connection_state_machine.h>
}

const int LDAP_DEBUG_ANY = -1;

const char* LDAP_DIRECTORY_ATTRS[] = { "objectClass", NULL };

typedef struct context_t
{
    struct ldap_global_context_t global_ctx;
    struct ldap_connection_ctx_t connection_ctx;
    struct ldap_connection_config_t config;
} context_t;

static struct context_t* create_context()
{
    context_t* ctx = static_cast<context_t*>(malloc(sizeof(context_t)));

    ctx->global_ctx.global_ldap = NULL;
    ctx->global_ctx.talloc_ctx = talloc_new(NULL);

    memset(&ctx->connection_ctx, 0, sizeof(ldap_connection_ctx_t));

    ctx->config.server = "ldap://dc0.example.alt";
    ctx->config.port = 389;
    ctx->config.protocol_verion = LDAP_VERSION3;

    ctx->config.use_sasl = false;
    ctx->config.use_start_tls = false;
    ctx->config.chase_referrals = false;

    return ctx;
}

static void destroy_context(struct context_t* ctx)
{
    if (ctx->connection_ctx.ldap_defaults)
    {
        if (ctx->connection_ctx.ldap_defaults->authcid)
        {
            ldap_memfree(ctx->connection_ctx.ldap_defaults->authcid);
        }

        if (ctx->connection_ctx.ldap_defaults->authzid)
        {
            ldap_memfree(ctx->connection_ctx.ldap_defaults->authzid);
        }

        if (ctx->connection_ctx.ldap_defaults->realm)
        {
            ldap_memfree(ctx->connection_ctx.ldap_defaults->realm);
        }
    }

    connection_close(&ctx->connection_ctx);
    talloc_free(ctx->global_ctx.talloc_ctx);
    free(ctx);
}

void connection_on_idle(verto_ctx *ctx, verto_ev *ev)
{
    (void)(ctx);
    ldap_connection_ctx_t* connection = static_cast<ldap_connection_ctx_t*>(verto_get_private(ev));

    csm_next_state(connection->state_machine);

    static int callcount = 0;

    fprintf(stderr, "Current callcount of idle function is: %d\n", ++callcount);

    if (connection->state_machine->state == LDAP_CONNECTION_STATE_RUN)
    {
        verto_del(ev);
        fprintf(stderr, "Removing idle event!\n");
    }
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    ctx = create_context();

    ctx->config.use_sasl = true;

    ctx->config.sasl_options = talloc(ctx->global_ctx.talloc_ctx, struct ldap_sasl_options_t);
    ctx->config.sasl_options->mechanism = "GSSAPI";
    ctx->config.sasl_options->passwd = NULL;

    ctx->config.sasl_options->sasl_nocanon = true;
    ctx->config.sasl_options->sasl_secprops = "maxssf=56";
    ctx->config.sasl_options->sasl_flags = LDAP_SASL_QUIET;
    ctx->connection_ctx.ldap_params = talloc(ctx->global_ctx.talloc_ctx, struct ldap_sasl_params_t);
    ctx->connection_ctx.ldap_params->dn = NULL;
    ctx->connection_ctx.ldap_params->passwd = talloc(ctx->global_ctx.talloc_ctx, struct berval);
    ctx->connection_ctx.ldap_params->passwd->bv_len = 0;
    ctx->connection_ctx.ldap_params->passwd->bv_val = NULL;
    ctx->connection_ctx.ldap_params->clientctrls = NULL;
    ctx->connection_ctx.ldap_params->serverctrls = NULL;

    int rc = RETURN_CODE_FAILURE;

    int debug_level = LDAP_DEBUG_ANY;
    ldap_set_option(ctx->connection_ctx.ldap, LDAP_OPT_DEBUG_LEVEL, &debug_level);

    rc = connection_configure(&ctx->global_ctx, &ctx->connection_ctx, &ctx->config);

    auto vertoEv = verto_add_timeout(ctx->connection_ctx.base, VERTO_EV_FLAG_PERSIST, connection_on_idle, 1000);
    verto_set_private(vertoEv, &ctx->connection_ctx, NULL);

    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    destroy_context(ctx);
    delete ui;
}

