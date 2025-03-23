import discord
from discord import app_commands
from discord.ext import commands, tasks
import datetime
import re
import time
import logging
import random
from typing import Optional
from collections import defaultdict, deque
import sqlite3
from datetime import timedelta, datetime

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("hypeprotect.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("HypeProtect")

# Intents Discord
intents = discord.Intents.all()
intents.message_content = True
intents.members = True
intents.presences = True
intents.guilds = True

# Initialisation du bot
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# Constantes
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 300  # 5 minutes en secondes
EMBED_COLOR = 0x2F3136
ERROR_COLOR = 0xFF0000
SUCCESS_COLOR = 0x00FF00
WARNING_COLOR = 0xFFD700
INFO_COLOR = 0x0000FF

# Structures de données en mémoire
deleted_messages = {}  # Pour la commande snipe
spam_counter = defaultdict(lambda: deque(maxlen=10))  # Pour l'anti-spam
message_cooldowns = defaultdict(dict)  # Pour les cooldowns
join_cooldown = defaultdict(list)  # Pour l'anti-raid

# Base de données
DB_PATH = "hypeprotect.db"

# Expressions régulières
INVITE_LINK_PATTERN = re.compile(r"(discord\.gg|discord\.com\/invite|discordapp\.com\/invite)\/[a-zA-Z0-9]+")
URL_PATTERN = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
MENTION_PATTERN = re.compile(r"<@!?\d+>")

# Liste de mots interdits (à compléter selon vos besoins)
BADWORDS = [
    "connard", "pute", "salope", "enculé", "fdp", "fils de pute", 
    "connasse", "salaud", "enfoiré", "bâtard", "putain", "merde", 
    "con", "conne", "bite", "couilles", "enculer", "foutre", "niquer", 
    "pd", "pédé", "nègre", "négro", "bougnoule", "nique", "ntm", "negro",
    "negro", "sale noir", "feuj", "youpin", "bicot", "bougnoule"
]

# Implémentation de la base de données
def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Table des configurations serveur
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS server_config (
        guild_id INTEGER PRIMARY KEY,
        anti_join INTEGER DEFAULT 0,
        anti_bot INTEGER DEFAULT 0,
        anti_nuke INTEGER DEFAULT 0,
        anti_badword INTEGER DEFAULT 0, 
        anti_everyone INTEGER DEFAULT 0,
        anti_ghostping INTEGER DEFAULT 0,
        anti_link INTEGER DEFAULT 0,
        anti_pub INTEGER DEFAULT 0,
        anti_spam INTEGER DEFAULT 0,
        anti_virus INTEGER DEFAULT 0,
        logs_channel_id INTEGER DEFAULT NULL
    )
    ''')
    
    # Table des utilisateurs en whitelist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER,
        user_id INTEGER,
        feature TEXT,  -- 'anti-lien', 'anti-pub', etc.
        added_by INTEGER,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(guild_id, user_id, feature)
    )
    ''')
    
    # Table des mutes temporaires
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS mutes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER,
        user_id INTEGER,
        moderator_id INTEGER,
        end_time TIMESTAMP,
        reason TEXT,
        active INTEGER DEFAULT 1,
        UNIQUE(guild_id, user_id, active)
    )
    ''')
    
    # Table pour les logs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER,
        user_id INTEGER,
        moderator_id INTEGER,
        action TEXT,
        reason TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Table pour les règles personnalisées
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS rules (
        guild_id INTEGER PRIMARY KEY,
        rules_text TEXT,
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Fonctions utilitaires pour la base de données
def get_server_config(guild_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM server_config WHERE guild_id = ?", (guild_id,))
    config = cursor.fetchone()
    
    if not config:
        cursor.execute("INSERT INTO server_config (guild_id) VALUES (?)", (guild_id,))
        conn.commit()
        cursor.execute("SELECT * FROM server_config WHERE guild_id = ?", (guild_id,))
        config = cursor.fetchone()
    
    conn.close()
    return dict(config) if config else None

def update_server_config(guild_id, feature, value):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(f"UPDATE server_config SET {feature} = ? WHERE guild_id = ?", (value, guild_id))
    conn.commit()
    
    conn.close()
    return True

def is_whitelisted(guild_id, user_id, feature):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM whitelist WHERE guild_id = ? AND user_id = ? AND feature = ?", 
        (guild_id, user_id, feature)
    )
    result = cursor.fetchone()
    
    conn.close()
    return bool(result)

def add_to_whitelist(guild_id, user_id, feature, added_by):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO whitelist (guild_id, user_id, feature, added_by) VALUES (?, ?, ?, ?)",
            (guild_id, user_id, feature, added_by)
        )
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    
    conn.close()
    return success

def remove_from_whitelist(guild_id, user_id, feature):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "DELETE FROM whitelist WHERE guild_id = ? AND user_id = ? AND feature = ?",
        (guild_id, user_id, feature)
    )
    conn.commit()
    
    success = cursor.rowcount > 0
    conn.close()
    return success

def get_whitelist(guild_id, feature=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if feature:
        cursor.execute(
            "SELECT * FROM whitelist WHERE guild_id = ? AND feature = ?",
            (guild_id, feature)
        )
    else:
        cursor.execute(
            "SELECT * FROM whitelist WHERE guild_id = ?",
            (guild_id,)
        )
    
    result = cursor.fetchall()
    conn.close()
    return [dict(row) for row in result]

def add_mute(guild_id, user_id, moderator_id, end_time, reason):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO mutes (guild_id, user_id, moderator_id, end_time, reason) VALUES (?, ?, ?, ?, ?)",
            (guild_id, user_id, moderator_id, end_time, reason)
        )
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        # Utilisateur déjà mute, mettre à jour la fin
        cursor.execute(
            "UPDATE mutes SET end_time = ?, moderator_id = ?, reason = ? WHERE guild_id = ? AND user_id = ? AND active = 1",
            (end_time, moderator_id, reason, guild_id, user_id)
        )
        conn.commit()
        success = cursor.rowcount > 0
    
    conn.close()
    return success

def remove_mute(guild_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE mutes SET active = 0 WHERE guild_id = ? AND user_id = ? AND active = 1",
        (guild_id, user_id)
    )
    conn.commit()
    
    success = cursor.rowcount > 0
    conn.close()
    return success

def get_active_mutes():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM mutes WHERE active = 1 AND end_time < datetime('now')"
    )
    
    result = cursor.fetchall()
    conn.close()
    return [dict(row) for row in result]

def add_log(guild_id, user_id, moderator_id, action, reason):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO logs (guild_id, user_id, moderator_id, action, reason) VALUES (?, ?, ?, ?, ?)",
        (guild_id, user_id, moderator_id, action, reason)
    )
    conn.commit()
    
    conn.close()
    return True

def get_logs(guild_id, user_id=None, limit=10):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if user_id:
        cursor.execute(
            "SELECT * FROM logs WHERE guild_id = ? AND user_id = ? ORDER BY timestamp DESC LIMIT ?",
            (guild_id, user_id, limit)
        )
    else:
        cursor.execute(
            "SELECT * FROM logs WHERE guild_id = ? ORDER BY timestamp DESC LIMIT ?",
            (guild_id, limit)
        )
    
    result = cursor.fetchall()
    conn.close()
    return [dict(row) for row in result]

def set_rules(guild_id, rules_text, created_by):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT OR REPLACE INTO rules (guild_id, rules_text, created_by) VALUES (?, ?, ?)",
        (guild_id, rules_text, created_by)
    )
    conn.commit()
    
    conn.close()
    return True

def get_rules(guild_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM rules WHERE guild_id = ?",
        (guild_id,)
    )
    
    result = cursor.fetchone()
    conn.close()
    return dict(result) if result else None

# Vérification des permissions
def is_admin(member):
    return member.guild_permissions.administrator

def is_mod(member):
    return (member.guild_permissions.kick_members or 
            member.guild_permissions.ban_members or 
            member.guild_permissions.manage_messages or
            is_admin(member))

def has_permission(ctx, permission):
    if isinstance(ctx, discord.Interaction):
        if not ctx.guild:
            return False
        member = ctx.user
    else:
        if not ctx.guild:
            return False
        member = ctx.author

    # Toujours autoriser l'administrateur du serveur
    if member.id == ctx.guild.owner_id:
        return True

    # Vérifier les permissions spécifiques
    if permission == "admin" and is_admin(member):
        return True
    elif permission == "mod" and is_mod(member):
        return True
    
    return False

# Fonctions utilitaires
def format_time(seconds):
    """Convertit un nombre de secondes en format lisible"""
    time_values = []
    values = [
        ("jour", 86400),
        ("heure", 3600),
        ("minute", 60),
        ("seconde", 1),
    ]
    
    for label, secs in values:
        qty = seconds // secs
        if qty:
            seconds -= qty * secs
            unit = label if qty == 1 else label + "s"
            time_values.append(f"{qty} {unit}")
    
    return ", ".join(time_values) if time_values else "0 seconde"

def time_to_seconds(time_str):
    """Convertit une chaîne de temps (1d, 2h, 3m, 4s) en secondes"""
    if not time_str:
        return 0
    
    total_seconds = 0
    time_mapping = {
        'd': 86400,  # jours
        'h': 3600,   # heures
        'm': 60,     # minutes
        's': 1       # secondes
    }
    
    pattern = re.compile(r'(\d+)([dhms])')
    matches = pattern.findall(time_str.lower())
    
    for value, unit in matches:
        total_seconds += int(value) * time_mapping.get(unit, 0)
    
    return total_seconds

async def log_action(guild, user, moderator, action, reason=None):
    """Enregistre une action dans la base de données et dans le canal de logs"""
    # Ajouter à la base de données
    guild_id = guild.id
    user_id = user.id if hasattr(user, 'id') else user
    moderator_id = moderator.id if hasattr(moderator, 'id') else (moderator or 0)
    
    add_log(guild_id, user_id, moderator_id, action, reason)
    
    # Récupérer le canal de logs
    config = get_server_config(guild_id)
    if not config or not config['logs_channel_id']:
        return
    
    logs_channel = guild.get_channel(config['logs_channel_id'])
    if not logs_channel:
        return
    
    # Créer un embed pour l'action
    embed = discord.Embed(
        title=f"📋 Action: {action}",
        color=EMBED_COLOR,
        timestamp=datetime.now()
    )
    
    # Ajouter les informations à l'embed
    if hasattr(user, 'name'):
        embed.add_field(name="Utilisateur", value=f"{user.mention} ({user.name})", inline=True)
    else:
        embed.add_field(name="Utilisateur ID", value=str(user_id), inline=True)
    
    if hasattr(moderator, 'name'):
        embed.add_field(name="Modérateur", value=f"{moderator.mention} ({moderator.name})", inline=True)
    elif moderator:
        embed.add_field(name="Modérateur ID", value=str(moderator_id), inline=True)
    
    if reason:
        embed.add_field(name="Raison", value=reason, inline=False)
    
    embed.set_footer(text=f"ID: {user_id}")
    
    # Envoyer l'embed
    try:
        await logs_channel.send(embed=embed)
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi du log: {e}")

# Tâche de vérification des mutes
@tasks.loop(seconds=30)
async def check_mutes():
    try:
        expired_mutes = get_active_mutes()
        
        for mute in expired_mutes:
            guild = bot.get_guild(mute['guild_id'])
            if not guild:
                continue
            
            member = guild.get_member(mute['user_id'])
            if not member:
                continue
            
            # Supprimer le rôle mute
            mute_role = discord.utils.get(guild.roles, name="HypeProtect-Muted")
            if mute_role and mute_role in member.roles:
                try:
                    await member.remove_roles(mute_role)
                    remove_mute(mute['guild_id'], mute['user_id'])
                    
                    # Log
                    await log_action(
                        guild, 
                        member, 
                        bot.user, 
                        "Unmute automatique", 
                        "Fin de la durée de mute"
                    )
                except Exception as e:
                    logger.error(f"Erreur lors du unmute automatique: {e}")
    except Exception as e:
        logger.error(f"Erreur dans la tâche check_mutes: {e}")

# Tâche de nettoyage des données temporaires
@tasks.loop(minutes=5)
async def cleanup_temporary_data():
    try:
        # Nettoyer les messages supprimés trop anciens
        current_time = time.time()
        for guild_id in list(deleted_messages.keys()):
            for channel_id in list(deleted_messages.get(guild_id, {}).keys()):
                deleted_messages[guild_id][channel_id] = [msg for msg in deleted_messages[guild_id].get(channel_id, []) 
                                                         if current_time - msg.get('timestamp', 0) < 3600]  # 1 heure
                
                if not deleted_messages[guild_id][channel_id]:
                    del deleted_messages[guild_id][channel_id]
            
            if not deleted_messages[guild_id]:
                del deleted_messages[guild_id]
        
        # Nettoyer d'autres données temporaires au besoin
    except Exception as e:
        logger.error(f"Erreur dans la tâche cleanup_temporary_data: {e}")

# Event Handlers
@bot.event
async def on_ready():
    logger.info(f"Bot connecté en tant que {bot.user.name}")
    
    # Initialiser la base de données
    init_database()
    
    # Démarrer les tâches
    check_mutes.start()
    cleanup_temporary_data.start()
    
    # Synchroniser les commandes slash
    try:
        synced = await bot.tree.sync()
        logger.info(f"{len(synced)} commandes synchronisées")
    except Exception as e:
        logger.error(f"Erreur lors de la synchronisation des commandes: {e}")

@bot.event
async def on_guild_join(guild):
    logger.info(f"Bot ajouté au serveur: {guild.name} (ID: {guild.id})")
    
    # Créer une configuration par défaut pour le serveur
    get_server_config(guild.id)
    
    # Créer un rôle mute s'il n'existe pas
    mute_role = discord.utils.get(guild.roles, name="HypeProtect-Muted")
    if not mute_role:
        try:
            mute_role = await guild.create_role(
                name="HypeProtect-Muted",
                reason="Rôle créé pour le système de mute de HypeProtect"
            )
            
            # Configurer les permissions du rôle
            for channel in guild.channels:
                try:
                    overwrite = discord.PermissionOverwrite()
                    overwrite.send_messages = False
                    overwrite.add_reactions = False
                    overwrite.speak = False
                    await channel.set_permissions(mute_role, overwrite=overwrite)
                except Exception as e:
                    logger.error(f"Erreur lors de la configuration des permissions: {e}")
        except Exception as e:
            logger.error(f"Erreur lors de la création du rôle mute: {e}")

@bot.event
async def on_member_join(member):
    guild = member.guild
    guild_id = guild.id
    
    config = get_server_config(guild_id)
    if not config:
        return
    
    # Anti-Bot
    if config['anti_bot'] and member.bot:
        if not is_whitelisted(guild_id, member.id, "anti-bot"):
            try:
                await member.kick(reason="Anti-Bot activé")
                await log_action(guild, member, bot.user, "Kick (Anti-Bot)", "Bot détecté automatiquement")
                return
            except Exception as e:
                logger.error(f"Erreur lors du kick d'un bot: {e}")
    
    # Anti-Join (Anti-Raid)
    if config['anti_join']:
        current_time = time.time()
        
        # Ajouter le membre à la liste
        join_cooldown[guild_id].append(current_time)
        
        # Supprimer les entrées trop anciennes (> 10 secondes)
        join_cooldown[guild_id] = [t for t in join_cooldown[guild_id] if current_time - t < 10]
        
        # Si plus de 5 membres ont rejoint en 10 secondes, activer le mode raid
        if len(join_cooldown[guild_id]) >= 5 and not is_whitelisted(guild_id, member.id, "anti-join"):
            try:
                await member.kick(reason="Protection anti-raid activée")
                await log_action(guild, member, bot.user, "Kick (Anti-Raid)", "Raid détecté automatiquement")
            except Exception as e:
                logger.error(f"Erreur lors du kick anti-raid: {e}")

@bot.event
async def on_member_ban(guild, user):
    await log_action(guild, user, None, "Ban", "Utilisateur banni")

@bot.event
async def on_member_unban(guild, user):
    await log_action(guild, user, None, "Unban", "Utilisateur débanni")

@bot.event
async def on_member_update(before, after):
    # Vérification des changements de rôles pour la protection anti-nuke
    guild = after.guild
    guild_id = guild.id
    
    config = get_server_config(guild_id)
    if not config or not config['anti_nuke']:
        return
    
    # Vérifier si des rôles d'administration ont été ajoutés
    added_roles = [role for role in after.roles if role not in before.roles]
    
    for role in added_roles:
        if role.permissions.administrator and not is_whitelisted(guild_id, after.id, "anti-nuke"):
            # Tentative de nuke détectée, retirer le rôle
            try:
                await after.remove_roles(role, reason="Protection anti-nuke")
                await log_action(
                    guild, 
                    after, 
                    bot.user, 
                    "Anti-Nuke", 
                    f"Rôle administrateur {role.name} retiré automatiquement"
                )
            except Exception as e:
                logger.error(f"Erreur lors de l'anti-nuke: {e}")

@bot.event
async def on_message(message):
    # Ignorer les messages du bot
    if message.author.bot:
        return
    
    # Ignorer les messages privés
    if not message.guild:
        return
    
    guild_id = message.guild.id
    config = get_server_config(guild_id)
    if not config:
        return
    
    # Traitement des commandes
    await bot.process_commands(message)
    
    # Vérifier si l'utilisateur est whitelisté pour toutes les fonctionnalités
    user_id = message.author.id
    
    # Ignorer les modérateurs pour certaines vérifications
    if is_mod(message.author):
        return
    
    # Anti-Badword
    if config['anti_badword'] and not is_whitelisted(guild_id, user_id, "anti-badword"):
        content_lower = message.content.lower()
        for word in BADWORDS:
            if word in content_lower:
                try:
                    await message.delete()
                    await message.channel.send(
                        f"{message.author.mention}, merci d'éviter l'utilisation de langage inapproprié.",
                        delete_after=5
                    )
                    await log_action(
                        message.guild, 
                        message.author, 
                        bot.user, 
                        "Anti-Badword", 
                        f"Message supprimé contenant: {word}"
                    )
                    return
                except Exception as e:
                    logger.error(f"Erreur lors de l'anti-badword: {e}")
    
    # Anti-Everyone
    if config['anti_everyone'] and not is_whitelisted(guild_id, user_id, "anti-everyone"):
        if "@everyone" in message.content or "@here" in message.content:
            if not message.author.guild_permissions.mention_everyone:
                try:
                    await message.delete()
                    await message.channel.send(
                        f"{message.author.mention}, vous n'êtes pas autorisé à mentionner everyone/here.",
                        delete_after=5
                    )
                    await log_action(
                        message.guild, 
                        message.author, 
                        bot.user, 
                        "Anti-Everyone", 
                        "Tentative de mention @everyone ou @here"
                    )
                    return
                except Exception as e:
                    logger.error(f"Erreur lors de l'anti-everyone: {e}")
    
    # Anti-Link
    if config['anti_link'] and not is_whitelisted(guild_id, user_id, "anti-lien"):
        if URL_PATTERN.search(message.content):
            try:
                await message.delete()
                await message.channel.send(
                    f"{message.author.mention}, les liens ne sont pas autorisés dans ce serveur.",
                    delete_after=5
                )
                await log_action(
                    message.guild, 
                    message.author, 
                    bot.user, 
                    "Anti-Lien", 
                    "Message avec lien supprimé"
                )
                return
            except Exception as e:
                logger.error(f"Erreur lors de l'anti-lien: {e}")
    
    # Anti-Pub
    if config['anti_pub'] and not is_whitelisted(guild_id, user_id, "anti-pub"):
        if INVITE_LINK_PATTERN.search(message.content):
            try:
                await message.delete()
                await message.channel.send(
                    f"{message.author.mention}, la publicité pour d'autres serveurs n'est pas autorisée.",
                    delete_after=5
                )
                await log_action(
                    message.guild, 
                    message.author, 
                    bot.user, 
                    "Anti-Pub", 
                    "Message avec invitation Discord supprimé"
                )
                return
            except Exception as e:
                logger.error(f"Erreur lors de l'anti-pub: {e}")
    
    # Anti-Spam
    if config['anti_spam'] and not is_whitelisted(guild_id, user_id, "anti-spam"):
        user_key = f"{guild_id}_{user_id}"
        
        # Ajouter le message à la file
        current_time = time.time()
        spam_counter[user_key].append(current_time)
        
        # Si l'utilisateur envoie plus de 5 messages en 3 secondes
        if len(spam_counter[user_key]) >= 5:
            oldest = spam_counter[user_key][0]
            if current_time - oldest < 3:
                # Trouver ou créer le rôle mute
                mute_role = discord.utils.get(message.guild.roles, name="HypeProtect-Muted")
                if not mute_role:
                    try:
                        mute_role = await message.guild.create_role(
                            name="HypeProtect-Muted",
                            reason="Rôle créé pour le système de mute de HypeProtect"
                        )
                        
                        # Configurer les permissions du rôle
                        for channel in message.guild.channels:
                            overwrite = discord.PermissionOverwrite()
                            overwrite.send_messages = False
                            overwrite.add_reactions = False
                            overwrite.speak = False
                            await channel.set_permissions(mute_role, overwrite=overwrite)
                    except Exception as e:
                        logger.error(f"Erreur lors de la création du rôle mute: {e}")
                        return
                
                try:
                    # Mute temporaire (5 minutes)
                    end_time = datetime.now() + timedelta(minutes=5)
                    add_mute(guild_id, user_id, bot.user.id, end_time, "Spam détecté")
                    
                    await message.author.add_roles(mute_role)
                    await message.channel.send(
                        f"{message.author.mention} a été mute pour 5 minutes pour spam.",
                        delete_after=10
                    )
                    
                    await log_action(
                        message.guild, 
                        message.author, 
                        bot.user, 
                        "Mute temporaire (Anti-Spam)", 
                        "Spam détecté automatiquement"
                    )
                except Exception as e:
                    logger.error(f"Erreur lors du mute anti-spam: {e}")
    
    # Anti-Virus (détection de liens suspects)
    if config['anti_virus'] and not is_whitelisted(guild_id, user_id, "anti-virus"):
        suspicious_domains = [
            "bit.ly", "goo.gl", "tinyurl.com", "is.gd", "shortened", 
            "free-nitro", "discord-nitro", "steamcommunityu", "dlscord", 
            "discordgift", "discordc", "discorcl", "dlscordapp"
        ]
        
        for domain in suspicious_domains:
            if domain in message.content.lower():
                try:
                    await message.delete()
                    await message.channel.send(
                        f"{message.author.mention}, votre message contient un lien potentiellement dangereux.",
                        delete_after=10
                    )
                    await log_action(
                        message.guild, 
                        message.author, 
                        bot.user, 
                        "Anti-Virus", 
                        f"Message avec lien suspect supprimé: {domain}"
                    )
                    return
                except Exception as e:
                    logger.error(f"Erreur lors de l'anti-virus: {e}")

@bot.event
async def on_message_delete(message):
    # Stocker le message supprimé pour la commande snipe
    if message.author.bot:
        return
    
    guild_id = message.guild.id
    channel_id = message.channel.id
    
    if guild_id not in deleted_messages:
        deleted_messages[guild_id] = {}
    
    if channel_id not in deleted_messages[guild_id]:
        deleted_messages[guild_id][channel_id] = []
    
    # Limiter à 10 messages par salon
    if len(deleted_messages[guild_id][channel_id]) >= 10:
        deleted_messages[guild_id][channel_id].pop(0)
    
    # Stocker les informations du message
    deleted_messages[guild_id][channel_id].append({
        'author': message.author,
        'content': message.content,
        'timestamp': time.time(),
        'attachments': [a.url for a in message.attachments]
    })
    
    # Anti-Ghostping
    config = get_server_config(guild_id)
    if not config or not config['anti_ghostping']:
        return
    
    # Vérifier les mentions dans le message
    if not MENTION_PATTERN.search(message.content):
        return
    
    # Ignorer si l'utilisateur est whitelist
    if is_whitelisted(guild_id, message.author.id, "anti-ghostping") or is_mod(message.author):
        return
    
    # Alerter d'un ghostping
    try:
        mentioned_users = [f"<@{user.id}>" for user in message.mentions if not user.bot]
        if mentioned_users:
            embed = discord.Embed(
                title="⚠️ Ghostping Détecté",
                description=f"{message.author.mention} a supprimé un message qui mentionnait des utilisateurs.",
                color=WARNING_COLOR
            )
            embed.add_field(name="Contenu du message", value=message.content[:1024] or "Contenu vide", inline=False)
            embed.add_field(name="Utilisateurs mentionnés", value=", ".join(mentioned_users) or "Aucun", inline=False)
            embed.set_footer(text=f"ID: {message.author.id}")
            
            await message.channel.send(embed=embed)
            
            await log_action(
                message.guild, 
                message.author, 
                bot.user, 
                "Anti-GhostPing", 
                f"Message avec mentions supprimé"
            )
    except Exception as e:
        logger.error(f"Erreur lors de l'anti-ghostping: {e}")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("Vous n'avez pas les permissions nécessaires pour exécuter cette commande.", delete_after=5)
        return
    
    logger.error(f"Erreur de commande: {error}")
    await ctx.send(f"Une erreur s'est produite: {error}", delete_after=10)

@bot.tree.error
async def on_app_command_error(interaction, error):
    if isinstance(error, app_commands.CommandNotFound):
        return
    
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message(
            "Vous n'avez pas les permissions nécessaires pour exécuter cette commande.", 
            ephemeral=True
        )
        return
    
    logger.error(f"Erreur de commande slash: {error}")
    
    try:
        if interaction.response.is_done():
            await interaction.followup.send(f"Une erreur s'est produite: {error}", ephemeral=True)
        else:
            await interaction.response.send_message(f"Une erreur s'est produite: {error}", ephemeral=True)
    except Exception as e:
        logger.error(f"Erreur lors de la réponse d'erreur: {e}")

# Commandes Anti-Raid
@bot.tree.command(name="anti-bot", description="Activer ou désactiver le système d'anti bot")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_bot(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "admin"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_bot", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Bot",
        description=f"Le système anti-bot a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Bot", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="anti-join", description="Activer ou désactiver le système d'anti join")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_join(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "admin"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_join", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Join",
        description=f"Le système anti-join a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Join", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="anti-nuke", description="Activer ou désactiver le système d'anti nuke")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_nuke(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "admin"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_nuke", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Nuke",
        description=f"Le système anti-nuke a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Nuke", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

# Commandes Auto-Mod
@bot.tree.command(name="anti-badword", description="Activer ou désactiver le système d'anti insultes")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_badword(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_badword", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Badword",
        description=f"Le système anti-insultes a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Badword", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="anti-everyone", description="Activer ou désactiver le système d'anti everyone")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_everyone(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_everyone", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Everyone",
        description=f"Le système anti-everyone a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Everyone", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="anti-ghostping", description="Activer ou désactiver le système d'anti ghostping")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_ghostping(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_ghostping", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Ghostping",
        description=f"Le système anti-ghostping a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Ghostping", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="anti-lien", description="Activer ou désactiver le système d'anti lien")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_lien(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_link", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Lien",
        description=f"Le système anti-lien a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Lien", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="anti-pub", description="Activer ou désactiver le système d'anti publicité")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_pub(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_pub", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Pub",
        description=f"Le système anti-publicité a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Pub", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="anti-spam", description="Activer ou désactiver le système d'anti spam")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_spam(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_spam", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Spam",
        description=f"Le système anti-spam a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Spam", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="anti-virus", description="Activer ou désactiver le système d'anti virus")
@app_commands.describe(option="Choisissez une option")
@app_commands.choices(option=[
    app_commands.Choice(name="Activer", value="activate"),
    app_commands.Choice(name="Désactiver", value="deactivate")
])
async def anti_virus(interaction: discord.Interaction, option: str):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    value = 1 if option == "activate" else 0
    
    update_server_config(guild_id, "anti_virus", value)
    
    status = "activé" if value == 1 else "désactivé"
    
    embed = discord.Embed(
        title="Configuration Anti-Virus",
        description=f"Le système anti-virus a été {status} avec succès.",
        color=SUCCESS_COLOR if value == 1 else WARNING_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        f"Configuration Anti-Virus", 
        f"Système {status}"
    )
    
    await interaction.response.send_message(embed=embed)

# Commandes de Modération
@bot.tree.command(name="ban", description="Ban un utilisateur du serveur")
@app_commands.describe(
    utilisateur="L'utilisateur à bannir",
    raison="La raison du ban"
)
async def ban(interaction: discord.Interaction, utilisateur: discord.User, raison: Optional[str] = None):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    raison = raison or "Aucune raison spécifiée"
    
    try:
        await interaction.guild.ban(utilisateur, reason=raison)
        
        embed = discord.Embed(
            title="Utilisateur Banni",
            description=f"{utilisateur.mention} a été banni du serveur.",
            color=SUCCESS_COLOR
        )
        embed.add_field(name="Raison", value=raison, inline=False)
        embed.set_footer(text=f"ID: {utilisateur.id}")
        
        await log_action(
            interaction.guild, 
            utilisateur, 
            interaction.user, 
            "Ban", 
            raison
        )
        
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("Je n'ai pas les permissions nécessaires pour bannir cet utilisateur.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Une erreur s'est produite lors du bannissement: {e}", ephemeral=True)

@bot.tree.command(name="clear", description="Supprime un certain nombre de messages dans le salon actuel")
@app_commands.describe(nombre="Nombre de messages à supprimer")
async def clear(interaction: discord.Interaction, nombre: int):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    if nombre <= 0 or nombre > 100:
        await interaction.response.send_message("Le nombre de messages à supprimer doit être compris entre 1 et 100.", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    
    try:
        messages = await interaction.channel.purge(limit=nombre)
        
        await log_action(
            interaction.guild, 
            interaction.user, 
            interaction.user, 
            "Clear", 
            f"{len(messages)} messages supprimés dans {interaction.channel.mention}"
        )
        
        await interaction.followup.send(f"{len(messages)} messages ont été supprimés avec succès.", ephemeral=True)
    except discord.Forbidden:
        await interaction.followup.send("Je n'ai pas les permissions nécessaires pour supprimer des messages.", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"Une erreur s'est produite lors de la suppression des messages: {e}", ephemeral=True)

@bot.tree.command(name="mute", description="Mute un utilisateur temporairement")
@app_commands.describe(
    utilisateur="L'utilisateur à mute",
    durée="La durée du mute (ex. 10s, 1m, 2h, 1d)",
    raison="La raison du mute"
)
async def mute(
    interaction: discord.Interaction, 
    utilisateur: discord.Member, 
    durée: str, 
    raison: Optional[str] = None
):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    # Convertir la durée en secondes
    seconds = time_to_seconds(durée)
    if seconds <= 0:
        await interaction.response.send_message("Format de durée invalide. Utilisez par exemple: 10s, 5m, 2h, 1d", ephemeral=True)
        return
    
    # Trouver ou créer le rôle mute
    mute_role = discord.utils.get(interaction.guild.roles, name="HypeProtect-Muted")
    if not mute_role:
        try:
            mute_role = await interaction.guild.create_role(
                name="HypeProtect-Muted",
                reason="Rôle créé pour le système de mute de HypeProtect"
            )
            
            # Configurer les permissions du rôle
            for channel in interaction.guild.channels:
                overwrite = discord.PermissionOverwrite()
                overwrite.send_messages = False
                overwrite.add_reactions = False
                overwrite.speak = False
                await channel.set_permissions(mute_role, overwrite=overwrite)
        except Exception as e:
            await interaction.response.send_message(f"Erreur lors de la création du rôle mute: {e}", ephemeral=True)
            return
    
    # Ajouter le rôle mute
    try:
        raison = raison or "Aucune raison spécifiée"
        end_time = datetime.now() + timedelta(seconds=seconds)
        
        add_mute(interaction.guild.id, utilisateur.id, interaction.user.id, end_time, raison)
        
        await utilisateur.add_roles(mute_role, reason=raison)
        
        readable_time = format_time(seconds)
        
        embed = discord.Embed(
            title="Utilisateur Mute",
            description=f"{utilisateur.mention} a été mute pour {readable_time}.",
            color=SUCCESS_COLOR
        )
        embed.add_field(name="Raison", value=raison, inline=False)
        embed.set_footer(text=f"ID: {utilisateur.id}")
        
        await log_action(
            interaction.guild, 
            utilisateur, 
            interaction.user, 
            "Mute", 
            f"Durée: {readable_time} | Raison: {raison}"
        )
        
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("Je n'ai pas les permissions nécessaires pour mute cet utilisateur.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Une erreur s'est produite lors du mute: {e}", ephemeral=True)

@bot.tree.command(name="snipe", description="Affiche le dernier message supprimé dans ce salon")
async def snipe(interaction: discord.Interaction):
    guild_id = interaction.guild.id
    channel_id = interaction.channel.id
    
    if (guild_id not in deleted_messages or 
        channel_id not in deleted_messages[guild_id] or 
        not deleted_messages[guild_id][channel_id]):
        await interaction.response.send_message("Aucun message supprimé récemment dans ce salon.", ephemeral=True)
        return
    
    # Récupérer le dernier message supprimé
    message_data = deleted_messages[guild_id][channel_id][-1]
    author = message_data['author']
    content = message_data['content'] or "*Contenu vide*"
    timestamp = datetime.fromtimestamp(message_data['timestamp'])
    attachments = message_data['attachments']
    
    embed = discord.Embed(
        title="Message Supprimé",
        description=content,
        color=EMBED_COLOR,
        timestamp=timestamp
    )
    embed.set_author(name=f"{author.name}", icon_url=author.avatar.url if author.avatar else None)
    
    if attachments:
        embed.add_field(name="Pièces jointes", value="\n".join(attachments), inline=False)
    
    embed.set_footer(text=f"Message supprimé par {author.name}")
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="unban", description="Débannit un utilisateur du serveur")
@app_commands.describe(
    utilisateur="L'utilisateur à débannir (ID requis)",
    raison="La raison du débannissement"
)
async def unban(interaction: discord.Interaction, utilisateur: str, raison: Optional[str] = None):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    try:
        # Vérifier si l'ID est valide
        user_id = int(utilisateur)
    except ValueError:
        await interaction.response.send_message("ID d'utilisateur invalide. Veuillez fournir un ID numérique.", ephemeral=True)
        return
    
    raison = raison or "Aucune raison spécifiée"
    
    try:
        # Récupérer les bans du serveur
        bans = [ban_entry async for ban_entry in interaction.guild.bans()]
        banned_user = discord.utils.get(bans, user__id=user_id)
        
        if not banned_user:
            await interaction.response.send_message("Cet utilisateur n'est pas banni du serveur.", ephemeral=True)
            return
        
        # Débannir l'utilisateur
        await interaction.guild.unban(banned_user.user, reason=raison)
        
        embed = discord.Embed(
            title="Utilisateur Débanni",
            description=f"**{banned_user.user.name}** a été débanni du serveur.",
            color=SUCCESS_COLOR
        )
        embed.add_field(name="Raison", value=raison, inline=False)
        embed.set_footer(text=f"ID: {banned_user.user.id}")
        
        await log_action(
            interaction.guild, 
            banned_user.user, 
            interaction.user, 
            "Unban", 
            raison
        )
        
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("Je n'ai pas les permissions nécessaires pour débannir cet utilisateur.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Une erreur s'est produite lors du débannissement: {e}", ephemeral=True)

@bot.tree.command(name="unmute", description="Supprime le mute d'un utilisateur")
@app_commands.describe(
    utilisateur="L'utilisateur à unmute",
    raison="La raison de la suppression du mute"
)
async def unmute(interaction: discord.Interaction, utilisateur: discord.Member, raison: Optional[str] = None):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    # Trouver le rôle mute
    mute_role = discord.utils.get(interaction.guild.roles, name="HypeProtect-Muted")
    if not mute_role:
        await interaction.response.send_message("Le rôle mute n'a pas été trouvé.", ephemeral=True)
        return
    
    # Vérifier si l'utilisateur est mute
    if mute_role not in utilisateur.roles:
        await interaction.response.send_message("Cet utilisateur n'est pas mute.", ephemeral=True)
        return
    
    raison = raison or "Aucune raison spécifiée"
    
    try:
        # Retirer le rôle mute
        await utilisateur.remove_roles(mute_role, reason=raison)
        
        # Mettre à jour la base de données
        remove_mute(interaction.guild.id, utilisateur.id)
        
        embed = discord.Embed(
            title="Utilisateur Unmute",
            description=f"{utilisateur.mention} a été unmute.",
            color=SUCCESS_COLOR
        )
        embed.add_field(name="Raison", value=raison, inline=False)
        embed.set_footer(text=f"ID: {utilisateur.id}")
        
        await log_action(
            interaction.guild, 
            utilisateur, 
            interaction.user, 
            "Unmute", 
            raison
        )
        
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("Je n'ai pas les permissions nécessaires pour unmute cet utilisateur.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Une erreur s'est produite lors du unmute: {e}", ephemeral=True)

# Commandes Bot
@bot.tree.command(name="help", description="Affiche la liste des commandes")
async def help(interaction: discord.Interaction):
    embed = discord.Embed(
        title="HypeProtect - Aide",
        description="Voici la liste des commandes disponibles:",
        color=EMBED_COLOR
    )
    
    # Catégorie Anti-Raid
    anti_raid_commands = (
        "`/anti-bot` - Activer ou désactiver le système d'anti bot\n"
        "`/anti-join` - Activer ou désactiver le système d'anti join\n"
        "`/anti-nuke` - Activer ou désactiver le système d'anti nuke"
    )
    embed.add_field(name="🛡️ Anti-Raid", value=anti_raid_commands, inline=False)
    
    # Catégorie Auto-Mod
    auto_mod_commands = (
        "`/anti-badword` - Activer ou désactiver le système d'anti insultes\n"
        "`/anti-everyone` - Activer ou désactiver le système d'anti everyone\n"
        "`/anti-ghostping` - Activer ou désactiver le système d'anti ghostping\n"
        "`/anti-lien` - Activer ou désactiver le système d'anti lien\n"
        "`/anti-pub` - Activer ou désactiver le système d'anti publicité\n"
        "`/anti-spam` - Activer ou désactiver le système d'anti spam\n"
        "`/anti-virus` - Activer ou désactiver le système d'anti virus"
    )
    embed.add_field(name="🤖 Auto-Mod", value=auto_mod_commands, inline=False)
    
    # Catégorie Modération
    moderation_commands = (
        "`/ban` - Ban un utilisateur du serveur\n"
        "`/clear` - Supprime un certain nombre de messages dans le salon actuel\n"
        "`/mute` - Mute un utilisateur temporairement\n"
        "`/snipe` - Affiche le dernier message supprimé dans ce salon\n"
        "`/unban` - Débannit un utilisateur du serveur\n"
        "`/unmute` - Supprime le mute d'un utilisateur"
    )
    embed.add_field(name="🔨 Modération", value=moderation_commands, inline=False)
    
    # Catégorie Bot
    bot_commands = (
        "`/help` - Affiche la liste des commandes\n"
        "`/ping` - Affiche la latence du bot\n"
        "`/whitelist` - Gère la liste blanche des utilisateurs\n"
        "`/whitelist anti-lien` - Gère la whitelist pour les liens\n"
        "`/whitelist anti-pub` - Gère la whitelist pour les publicités\n"
        "`/whitelist anti-ghostping` - Gère la whitelist pour le ghostping\n"
        "`/whitelist anti-bot` - Gère la whitelist pour les bots\n"
        "`/whitelist anti-join` - Gère la whitelist pour les raids\n"
        "`/whitelist anti-nuke` - Gère la whitelist pour le nuke\n"
        "`/whitelist liste` - Affiche la liste des utilisateurs whitelist"
    )
    embed.add_field(name="🤖 Bot", value=bot_commands, inline=False)
    
    # Catégorie Informations
    info_commands = (
        "`/all-admin` - Affiche tous les utilisateurs avec les permissions d'admin\n"
        "`/all-bot` - Affiche tous les bots présents dans ce serveur\n"
        "`/banlist` - Affiche la liste des bannissements\n"
        "`/config` - Vérifie les configurations des systèmes\n"
        "`/info emoji` - Affiche les informations d'un emoji spécifique\n"
        "`/info salon` - Affiche les informations sur un salon\n"
        "`/info serveur` - Affiche les informations sur le serveur\n"
        "`/info utilisateur` - Affiche les informations sur un utilisateur"
    )
    embed.add_field(name="ℹ️ Informations", value=info_commands, inline=False)
    
    # Catégorie Autres
    autres_commands = (
        "`/lock` - Bloque l'accès à l'écriture dans un salon\n"
        "`/logs` - Configure le salon des logs\n"
        "`/report` - Signale un utilisateur pour une raison spécifiée\n"
        "`/rules-create` - Crée un message de règlement dans le salon actuel\n"
        "`/sos` - Envoie une alerte SOS à l'équipe de modération\n"
        "`/unlock` - Débloque l'accès à l'écriture dans un salon"
    )
    embed.add_field(name="🔧 Autres", value=autres_commands, inline=False)
    
    embed.set_footer(text=f"HypeProtect v{VERSION} | Développé avec ❤️")
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="ping", description="Affiche la latence du bot, de la base de données et de l'API de Discord")
async def ping(interaction: discord.Interaction):
    # Mesurer la latence WebSocket
    websocket_latency = round(bot.latency * 1000)
    
    # Mesurer la latence de la base de données
    start_time = time.time()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    cursor.fetchone()
    conn.close()
    database_latency = round((time.time() - start_time) * 1000)
    
    # Mesurer la latence de l'API Discord
    api_start = time.time()
    await interaction.guild.fetch_channels()
    api_latency = round((time.time() - api_start) * 1000)
    
    embed = discord.Embed(
        title="🏓 Pong!",
        description="Voici les informations de latence du bot:",
        color=EMBED_COLOR
    )
    
    embed.add_field(name="Latence WebSocket", value=f"`{websocket_latency}ms`", inline=True)
    embed.add_field(name="Latence API", value=f"`{api_latency}ms`", inline=True)
    embed.add_field(name="Latence Base de données", value=f"`{database_latency}ms`", inline=True)
    
    embed.set_footer(text=f"HypeProtect v{VERSION}")
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="whitelist", description="Ajoute ou supprime un utilisateur de la whitelist d'une fonctionnalité")
@app_commands.describe(
    action="L'action à effectuer",
    utilisateur="L'utilisateur à whitelist",
    fonctionnalité="La fonctionnalité pour laquelle whitelist l'utilisateur"
)
@app_commands.choices(action=[
    app_commands.Choice(name="Ajouter", value="add"),
    app_commands.Choice(name="Supprimer", value="remove")
])
@app_commands.choices(fonctionnalité=[
    app_commands.Choice(name="Anti-Lien", value="anti-lien"),
    app_commands.Choice(name="Anti-Pub", value="anti-pub"),
    app_commands.Choice(name="Anti-GhostPing", value="anti-ghostping"),
    app_commands.Choice(name="Anti-Bot", value="anti-bot"),
    app_commands.Choice(name="Anti-Join", value="anti-join"),
    app_commands.Choice(name="Anti-Nuke", value="anti-nuke"),
    app_commands.Choice(name="Anti-Spam", value="anti-spam"),
    app_commands.Choice(name="Anti-Badword", value="anti-badword")
])
async def whitelist(
    interaction: discord.Interaction, 
    action: str, 
    utilisateur: discord.Member, 
    fonctionnalité: str
):
    if not has_permission(interaction, "admin"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    user_id = utilisateur.id
    
    if action == "add":
        # Ajouter à la whitelist
        success = add_to_whitelist(guild_id, user_id, fonctionnalité, interaction.user.id)
        
        if success:
            embed = discord.Embed(
                title="Whitelist - Ajout",
                description=f"{utilisateur.mention} a été ajouté à la whitelist pour la fonctionnalité `{fonctionnalité}`.",
                color=SUCCESS_COLOR
            )
            
            await log_action(
                interaction.guild, 
                utilisateur, 
                interaction.user, 
                "Whitelist Ajout", 
                f"Fonctionnalité: {fonctionnalité}"
            )
        else:
            embed = discord.Embed(
                title="Whitelist - Erreur",
                description=f"{utilisateur.mention} est déjà dans la whitelist pour la fonctionnalité `{fonctionnalité}`.",
                color=WARNING_COLOR
            )
    else:
        # Supprimer de la whitelist
        success = remove_from_whitelist(guild_id, user_id, fonctionnalité)
        
        if success:
            embed = discord.Embed(
                title="Whitelist - Suppression",
                description=f"{utilisateur.mention} a été retiré de la whitelist pour la fonctionnalité `{fonctionnalité}`.",
                color=WARNING_COLOR
            )
            
            await log_action(
                interaction.guild, 
                utilisateur, 
                interaction.user, 
                "Whitelist Suppression", 
                f"Fonctionnalité: {fonctionnalité}"
            )
        else:
            embed = discord.Embed(
                title="Whitelist - Erreur",
                description=f"{utilisateur.mention} n'est pas dans la whitelist pour la fonctionnalité `{fonctionnalité}`.",
                color=ERROR_COLOR
            )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="whitelist-liste", description="Affiche la liste des utilisateurs whitelist")
@app_commands.describe(fonctionnalité="La fonctionnalité pour laquelle afficher la whitelist")
@app_commands.choices(fonctionnalité=[
    app_commands.Choice(name="Anti-Lien", value="anti-lien"),
    app_commands.Choice(name="Anti-Pub", value="anti-pub"),
    app_commands.Choice(name="Anti-GhostPing", value="anti-ghostping"),
    app_commands.Choice(name="Anti-Bot", value="anti-bot"),
    app_commands.Choice(name="Anti-Join", value="anti-join"),
    app_commands.Choice(name="Anti-Nuke", value="anti-nuke"),
    app_commands.Choice(name="Anti-Spam", value="anti-spam"),
    app_commands.Choice(name="Anti-Badword", value="anti-badword"),
    app_commands.Choice(name="Toutes", value="all")
])
async def whitelist_liste(interaction: discord.Interaction, fonctionnalité: Optional[str] = "all"):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    
    if fonctionnalité == "all":
        whitelist_entries = get_whitelist(guild_id)
        title = "Whitelist - Toutes les fonctionnalités"
    else:
        whitelist_entries = get_whitelist(guild_id, fonctionnalité)
        title = f"Whitelist - {fonctionnalité}"
    
    if not whitelist_entries:
        embed = discord.Embed(
            title=title,
            description="Aucun utilisateur dans la whitelist.",
            color=WARNING_COLOR
        )
        await interaction.response.send_message(embed=embed)
        return
    
    # Regrouper par fonctionnalité
    whitelist_by_feature = {}
    for entry in whitelist_entries:
        feature = entry['feature']
        if feature not in whitelist_by_feature:
            whitelist_by_feature[feature] = []
        
        user_id = entry['user_id']
        member = interaction.guild.get_member(user_id)
        user_name = member.name if member else f"ID: {user_id}"
        
        whitelist_by_feature[feature].append(f"<@{user_id}> ({user_name})")
    
    embed = discord.Embed(
        title=title,
        description="Voici les utilisateurs dans la whitelist:",
        color=EMBED_COLOR
    )
    
    for feature, users in whitelist_by_feature.items():
        embed.add_field(
            name=feature,
            value="\n".join(users) or "Aucun utilisateur",
            inline=False
        )
    
    await interaction.response.send_message(embed=embed)

# Commandes d'informations
@bot.tree.command(name="all-admin", description="Affiche tous les utilisateurs ayant la permission d'administrateur dans ce serveur")
async def all_admin(interaction: discord.Interaction):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    await interaction.response.defer()
    
    admins = [member for member in interaction.guild.members if member.guild_permissions.administrator]
    
    if not admins:
        embed = discord.Embed(
            title="Administrateurs",
            description="Aucun utilisateur avec des permissions d'administrateur n'a été trouvé.",
            color=WARNING_COLOR
        )
        await interaction.followup.send(embed=embed)
        return
    
    # Trier par nom
    admins.sort(key=lambda m: m.name.lower())
    
    embed = discord.Embed(
        title="Administrateurs",
        description=f"Liste des utilisateurs avec des permissions d'administrateur ({len(admins)}):",
        color=EMBED_COLOR
    )
    
    # Diviser en plusieurs champs si nécessaire
    chunks = [admins[i:i + 10] for i in range(0, len(admins), 10)]
    
    for i, chunk in enumerate(chunks):
        admin_list = "\n".join([f"{admin.mention} ({admin.name})" for admin in chunk])
        embed.add_field(name=f"Administrateurs {i+1}", value=admin_list, inline=False)
    
    await interaction.followup.send(embed=embed)

@bot.tree.command(name="all-bot", description="Affiche tous les bots présents dans ce serveur")
async def all_bot(interaction: discord.Interaction):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    await interaction.response.defer()
    
    bots = [member for member in interaction.guild.members if member.bot]
    
    if not bots:
        embed = discord.Embed(
            title="Bots",
            description="Aucun bot n'a été trouvé sur ce serveur.",
            color=WARNING_COLOR
        )
        await interaction.followup.send(embed=embed)
        return
    
    # Trier par nom
    bots.sort(key=lambda m: m.name.lower())
    
    embed = discord.Embed(
        title="Bots",
        description=f"Liste des bots présents sur ce serveur ({len(bots)}):",
        color=EMBED_COLOR
    )
    
    # Diviser en plusieurs champs si nécessaire
    chunks = [bots[i:i + 10] for i in range(0, len(bots), 10)]
    
    for i, chunk in enumerate(chunks):
        bot_list = "\n".join([f"{bot.mention} ({bot.name})" for bot in chunk])
        embed.add_field(name=f"Bots {i+1}", value=bot_list, inline=False)
    
    await interaction.followup.send(embed=embed)

@bot.tree.command(name="banlist", description="Affiche la liste des bannissements")
async def banlist(interaction: discord.Interaction):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    await interaction.response.defer()
    
    try:
        bans = [ban_entry async for ban_entry in interaction.guild.bans()]
        
        if not bans:
            embed = discord.Embed(
                title="Liste des bannissements",
                description="Aucun utilisateur banni n'a été trouvé.",
                color=WARNING_COLOR
            )
            await interaction.followup.send(embed=embed)
            return
        
        # Trier par nom
        bans.sort(key=lambda b: b.user.name.lower())
        
        embed = discord.Embed(
            title="Liste des bannissements",
            description=f"Liste des utilisateurs bannis ({len(bans)}):",
            color=EMBED_COLOR
        )
        
        # Diviser en plusieurs champs si nécessaire
        chunks = [bans[i:i + 10] for i in range(0, len(bans), 10)]
        
        for i, chunk in enumerate(chunks):
            ban_list = "\n".join([f"**{ban.user.name}** (ID: {ban.user.id})\nRaison: {ban.reason or 'Aucune raison spécifiée'}" for ban in chunk])
            embed.add_field(name=f"Bannis {i+1}", value=ban_list, inline=False)
        
        await interaction.followup.send(embed=embed)
    except discord.Forbidden:
        await interaction.followup.send("Je n'ai pas les permissions nécessaires pour voir la liste des bannissements.", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"Une erreur s'est produite: {e}", ephemeral=True)

@bot.tree.command(name="config", description="Vérifie et gère les configurations des systèmes de protection")
async def config(interaction: discord.Interaction):
    if not has_permission(interaction, "admin"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    config = get_server_config(guild_id)
    
    if not config:
        await interaction.response.send_message("La configuration du serveur n'a pas été trouvée.", ephemeral=True)
        return
    
    # Construire l'embed avec les configurations
    embed = discord.Embed(
        title="Configuration HypeProtect",
        description="Voici la configuration actuelle des systèmes de protection:",
        color=EMBED_COLOR
    )
    
    # Anti-Raid
    anti_raid_config = (
        f"Anti-Bot: {'✅ Activé' if config['anti_bot'] else '❌ Désactivé'}\n"
        f"Anti-Join: {'✅ Activé' if config['anti_join'] else '❌ Désactivé'}\n"
        f"Anti-Nuke: {'✅ Activé' if config['anti_nuke'] else '❌ Désactivé'}"
    )
    embed.add_field(name="🛡️ Anti-Raid", value=anti_raid_config, inline=False)
    
    # Auto-Mod
    auto_mod_config = (
        f"Anti-Badword: {'✅ Activé' if config['anti_badword'] else '❌ Désactivé'}\n"
        f"Anti-Everyone: {'✅ Activé' if config['anti_everyone'] else '❌ Désactivé'}\n"
        f"Anti-GhostPing: {'✅ Activé' if config['anti_ghostping'] else '❌ Désactivé'}\n"
        f"Anti-Lien: {'✅ Activé' if config['anti_link'] else '❌ Désactivé'}\n"
        f"Anti-Pub: {'✅ Activé' if config['anti_pub'] else '❌ Désactivé'}\n"
        f"Anti-Spam: {'✅ Activé' if config['anti_spam'] else '❌ Désactivé'}\n"
        f"Anti-Virus: {'✅ Activé' if config['anti_virus'] else '❌ Désactivé'}"
    )
    embed.add_field(name="🤖 Auto-Mod", value=auto_mod_config, inline=False)
    
    # Logs
    logs_channel = None
    if config['logs_channel_id']:
        logs_channel = interaction.guild.get_channel(config['logs_channel_id'])
    
    logs_config = f"Salon de logs: {logs_channel.mention if logs_channel else '❌ Non configuré'}"
    embed.add_field(name="📋 Logs", value=logs_config, inline=False)
    
    embed.set_footer(text=f"HypeProtect v{VERSION} | Utilisez /help pour voir toutes les commandes")
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="info", description="Affiche des informations spécifiques")
async def info(interaction: discord.Interaction):
    pass

@info.command(name="emoji", description="Affiche les informations d'un emoji spécifique")
@app_commands.describe(emoji="Emoji à analyser")
async def info_emoji(interaction: discord.Interaction, emoji: str):
    # Vérifier si c'est un emoji personnalisé
    custom_emoji_pattern = re.compile(r'<a?:([\w]+):(\d+)>')
    match = custom_emoji_pattern.match(emoji)
    
    embed = discord.Embed(
        title="Informations sur l'emoji",
        color=EMBED_COLOR
    )
    
    if match:
        # Emoji personnalisé
        emoji_name = match.group(1)
        emoji_id = match.group(2)
        is_animated = emoji.startswith('<a:')
        
        embed.add_field(name="Nom", value=emoji_name, inline=True)
        embed.add_field(name="ID", value=emoji_id, inline=True)
        embed.add_field(name="Animé", value="Oui" if is_animated else "Non", inline=True)
        
        # URL de l'emoji
        extension = 'gif' if is_animated else 'png'
        emoji_url = f"https://cdn.discordapp.com/emojis/{emoji_id}.{extension}?v=1"
        
        embed.add_field(name="URL", value=f"[Lien]({emoji_url})", inline=True)
        embed.set_thumbnail(url=emoji_url)
    else:
        # Emoji standard
        embed.description = f"Emoji standard: {emoji}"
        
        # Essayer de récupérer le nom Unicode
        try:
            import unicodedata
            emoji_name = unicodedata.name(emoji)
            embed.add_field(name="Nom Unicode", value=emoji_name, inline=False)
        except:
            pass
        
        # Codepoints
        codepoints = [f"U+{ord(c):04X}" for c in emoji]
        embed.add_field(name="Codepoints", value=" ".join(codepoints), inline=False)
    
    await interaction.response.send_message(embed=embed)

@info.command(name="salon", description="Affiche les informations sur un salon spécifique ou le salon actuel")
@app_commands.describe(salon="Salon à analyser")
async def info_salon(interaction: discord.Interaction, salon: Optional[discord.abc.GuildChannel] = None):
    channel = salon or interaction.channel
    
    embed = discord.Embed(
        title=f"Informations sur le salon #{channel.name}",
        color=EMBED_COLOR
    )
    
    # Informations de base
    embed.add_field(name="ID", value=channel.id, inline=True)
    embed.add_field(name="Type", value=str(channel.type).replace('_', ' ').title(), inline=True)
    embed.add_field(name="Position", value=channel.position, inline=True)
    
    # Date de création
    created_at = channel.created_at.strftime("%d/%m/%Y %H:%M:%S")
    embed.add_field(name="Créé le", value=created_at, inline=True)
    
    # Informations spécifiques au type de salon
    if isinstance(channel, discord.TextChannel):
        embed.add_field(name="Slowmode", value=f"{channel.slowmode_delay} secondes" if channel.slowmode_delay else "Désactivé", inline=True)
        embed.add_field(name="NSFW", value="Oui" if channel.is_nsfw() else "Non", inline=True)
        if channel.topic:
            embed.add_field(name="Sujet", value=channel.topic, inline=False)
    elif isinstance(channel, discord.VoiceChannel):
        embed.add_field(name="Bitrate", value=f"{channel.bitrate//1000} kbps", inline=True)
        embed.add_field(name="Limite d'utilisateurs", value=channel.user_limit or "Illimité", inline=True)
    
    # Permissions
    overwrites = []
    for target, overwrite in channel.overwrites.items():
        if isinstance(target, discord.Role):
            overwrites.append(f"**Rôle:** {target.name}")
        else:
            overwrites.append(f"**Utilisateur:** {target.name}")
    
    if overwrites:
        embed.add_field(name="Permissions personnalisées", value=f"{len(overwrites)} modifications", inline=False)
    
    await interaction.response.send_message(embed=embed)

@info.command(name="serveur", description="Affiche les informations sur le serveur")
async def info_serveur(interaction: discord.Interaction):
    guild = interaction.guild
    
    embed = discord.Embed(
        title=f"Informations sur le serveur {guild.name}",
        color=EMBED_COLOR
    )
    
    # Informations de base
    embed.add_field(name="ID", value=guild.id, inline=True)
    embed.add_field(name="Propriétaire", value=f"{guild.owner.mention} ({guild.owner.name})" if guild.owner else "Inconnu", inline=True)
    embed.add_field(name="Créé le", value=guild.created_at.strftime("%d/%m/%Y %H:%M:%S"), inline=True)
    
    # Statistiques
    embed.add_field(name="Membres", value=guild.member_count, inline=True)
    embed.add_field(name="Salons", value=len(guild.channels), inline=True)
    embed.add_field(name="Rôles", value=len(guild.roles), inline=True)
    embed.add_field(name="Emojis", value=f"{len(guild.emojis)}/{guild.emoji_limit}", inline=True)
    embed.add_field(name="Stickers", value=f"{len(guild.stickers)}/{guild.sticker_limit}", inline=True)
    
    # Boost
    embed.add_field(name="Niveau de boost", value=f"Niveau {guild.premium_tier}", inline=True)
    embed.add_field(name="Boosters", value=guild.premium_subscription_count, inline=True)
    
    # Fonctionnalités
    if guild.features:
        features = ", ".join(f"`{feature}`" for feature in guild.features)
        embed.add_field(name="Fonctionnalités", value=features, inline=False)
    
    # Paramètres de vérification et de notifications
    embed.add_field(name="Niveau de vérification", value=str(guild.verification_level).replace('_', ' ').title(), inline=True)
    embed.add_field(name="Notifications par défaut", value=str(guild.default_notifications).replace('_', ' ').title(), inline=True)
    
    # Ajouter la bannière et l'icône
    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)
    
    if guild.banner:
        embed.set_image(url=guild.banner.url)
    
    await interaction.response.send_message(embed=embed)

@info.command(name="utilisateur", description="Obtenez des informations sur un utilisateur mentionné")
@app_commands.describe(user="L'utilisateur dont vous voulez obtenir des informations")
async def info_utilisateur(interaction: discord.Interaction, user: discord.Member):
    embed = discord.Embed(
        title=f"Informations sur {user.name}",
        color=user.color if user.color != discord.Color.default() else EMBED_COLOR
    )
    
    # Informations de base
    embed.add_field(name="ID", value=user.id, inline=True)
    embed.add_field(name="Nom d'utilisateur", value=user.name, inline=True)
    embed.add_field(name="Discriminateur", value=user.discriminator if hasattr(user, 'discriminator') and user.discriminator != '0' else "Aucun", inline=True)
    
    # Dates
    embed.add_field(name="Compte créé le", value=user.created_at.strftime("%d/%m/%Y %H:%M:%S"), inline=True)
    embed.add_field(name="A rejoint le", value=user.joined_at.strftime("%d/%m/%Y %H:%M:%S") if user.joined_at else "Inconnu", inline=True)
    
    # Status et activité
    status_mapping = {
        discord.Status.online: "🟢 En ligne",
        discord.Status.idle: "🟡 Inactif",
        discord.Status.dnd: "🔴 Ne pas déranger",
        discord.Status.offline: "⚪ Hors ligne"
    }
    
    embed.add_field(name="Statut", value=status_mapping.get(user.status, "Inconnu"), inline=True)
    
    if user.activity:
        activity_type = str(user.activity.type).split('.')[-1].replace('_', ' ').title()
        activity_name = user.activity.name
        embed.add_field(name="Activité", value=f"{activity_type} {activity_name}", inline=True)
    
    # Rôles
    roles = [role.mention for role in user.roles if role.name != "@everyone"]
    if roles:
        embed.add_field(name=f"Rôles ({len(roles)})", value=" ".join(roles) if len(roles) < 10 else " ".join(roles[:9]) + f" et {len(roles) - 9} de plus", inline=False)
    
    # Permissions notables
    permissions = []
    if user.guild_permissions.administrator:
        permissions.append("👑 Administrateur")
    elif user.guild_permissions.manage_guild:
        permissions.append("🛠️ Gérer le serveur")
    elif user.guild_permissions.ban_members:
        permissions.append("🔨 Bannir des membres")
    elif user.guild_permissions.kick_members:
        permissions.append("👢 Expulser des membres")
    elif user.guild_permissions.manage_messages:
        permissions.append("✏️ Gérer les messages")
    
    if permissions:
        embed.add_field(name="Permissions notables", value=", ".join(permissions), inline=False)
    
    # Avatars
    if user.avatar:
        embed.set_thumbnail(url=user.avatar.url)
    
    if user.guild_avatar:
        embed.add_field(name="Avatar de serveur", value=f"[Lien]({user.guild_avatar.url})", inline=True)
    
    # Badges
    badges = []
    if user.public_flags.staff:
        badges.append("👮 Staff Discord")
    if user.public_flags.partner:
        badges.append("🤝 Partenaire")
    if user.public_flags.hypesquad:
        badges.append("🏠 HypeSquad Events")
    if user.public_flags.bug_hunter:
        badges.append("🐛 Chasseur de bugs")
    if user.public_flags.bug_hunter_level_2:
        badges.append("🐛 Chasseur de bugs niveau 2")
    if user.public_flags.hypesquad_bravery:
        badges.append("🧡 HypeSquad Bravery")
    if user.public_flags.hypesquad_brilliance:
        badges.append("💜 HypeSquad Brilliance")
    if user.public_flags.hypesquad_balance:
        badges.append("💚 HypeSquad Balance")
    if user.public_flags.early_supporter:
        badges.append("🥇 Early Supporter")
    if user.public_flags.verified_bot_developer:
        badges.append("🤖 Développeur de bot vérifié")
    
    if badges:
        embed.add_field(name="Badges", value=", ".join(badges), inline=False)
    
    await interaction.response.send_message(embed=embed)

# Autres commandes
@bot.tree.command(name="lock", description="Bloque l'accès à l'écriture dans un salon")
@app_commands.describe(role="Le rôle à verrouiller (facultatif)")
async def lock(interaction: discord.Interaction, role: Optional[discord.Role] = None):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    channel = interaction.channel
    
    if role:
        # Verrouiller pour un rôle spécifique
        overwrite = channel.overwrites_for(role)
        overwrite.send_messages = False
        await channel.set_permissions(role, overwrite=overwrite)
        
        embed = discord.Embed(
            title="Salon verrouillé",
            description=f"Le salon {channel.mention} a été verrouillé pour le rôle {role.mention}.",
            color=WARNING_COLOR
        )
        
        await log_action(
            interaction.guild, 
            interaction.user, 
            interaction.user, 
            "Lock", 
            f"Salon {channel.name} verrouillé pour le rôle {role.name}"
        )
    else:
        # Verrouiller pour @everyone
        everyone = interaction.guild.default_role
        overwrite = channel.overwrites_for(everyone)
        overwrite.send_messages = False
        await channel.set_permissions(everyone, overwrite=overwrite)
        
        embed = discord.Embed(
            title="Salon verrouillé",
            description=f"Le salon {channel.mention} a été verrouillé pour tout le monde.",
            color=WARNING_COLOR
        )
        
        await log_action(
            interaction.guild, 
            interaction.user, 
            interaction.user, 
            "Lock", 
            f"Salon {channel.name} verrouillé pour tout le monde"
        )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="logs", description="Configure le salon des logs")
@app_commands.describe(salon="Le salon où les logs seront envoyés")
async def logs(interaction: discord.Interaction, salon: discord.TextChannel):
    if not has_permission(interaction, "admin"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    
    # Mettre à jour la configuration
    update_server_config(guild_id, "logs_channel_id", salon.id)
    
    embed = discord.Embed(
        title="Configuration des logs",
        description=f"Le salon des logs a été configuré sur {salon.mention}.",
        color=SUCCESS_COLOR
    )
    
    await log_action(
        interaction.guild, 
        interaction.user, 
        interaction.user, 
        "Configuration des logs", 
        f"Salon configuré: {salon.name}"
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="report", description="Signale un utilisateur pour une raison spécifiée")
@app_commands.describe(
    utilisateur="L'utilisateur à signaler",
    raison="La raison du signalement"
)
async def report(interaction: discord.Interaction, utilisateur: discord.User, raison: str):
    # Récupérer le salon de logs
    guild_id = interaction.guild.id
    config = get_server_config(guild_id)
    
    if not config or not config['logs_channel_id']:
        await interaction.response.send_message("Le système de signalement n'est pas configuré. Contactez un administrateur.", ephemeral=True)
        return
    
    logs_channel = interaction.guild.get_channel(config['logs_channel_id'])
    if not logs_channel:
        await interaction.response.send_message("Le salon de logs n'a pas été trouvé. Contactez un administrateur.", ephemeral=True)
        return
    
    # Créer l'embed de signalement
    embed = discord.Embed(
        title="📢 Signalement",
        description=f"Un utilisateur a été signalé par {interaction.user.mention}.",
        color=WARNING_COLOR,
        timestamp=datetime.now()
    )
    
    embed.add_field(name="Utilisateur signalé", value=f"{utilisateur.mention} ({utilisateur.name})", inline=True)
    embed.add_field(name="ID", value=utilisateur.id, inline=True)
    embed.add_field(name="Signalé par", value=f"{interaction.user.mention} ({interaction.user.name})", inline=True)
    embed.add_field(name="Raison", value=raison, inline=False)
    embed.add_field(name="Salon", value=interaction.channel.mention, inline=True)
    
    if utilisateur.avatar:
        embed.set_thumbnail(url=utilisateur.avatar.url)
    
    embed.set_footer(text=f"ID du signalement: {random.randint(100000, 999999)}")
    
    # Envoyer l'embed
    await logs_channel.send(embed=embed)
    
    # Confirmer à l'utilisateur
    confirmation_embed = discord.Embed(
        title="Signalement envoyé",
        description="Votre signalement a été envoyé à l'équipe de modération.",
        color=SUCCESS_COLOR
    )
    
    await log_action(
        interaction.guild, 
        utilisateur, 
        interaction.user, 
        "Signalement", 
        raison
    )
    
    await interaction.response.send_message(embed=confirmation_embed, ephemeral=True)

@bot.tree.command(name="rules-create", description="Crée un message de règlement dans le salon actuel")
async def rules_create(interaction: discord.Interaction):
    if not has_permission(interaction, "admin"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    # Envoyer un modal pour saisir les règles
    class RulesModal(discord.ui.Modal, title="Création des règles du serveur"):
        rules_content = discord.ui.TextInput(
            label="Contenu des règles",
            style=discord.TextStyle.paragraph,
            placeholder="Entrez les règles du serveur ici...",
            required=True,
            max_length=4000
        )
        
        async def on_submit(self, interaction: discord.Interaction):
            # Créer l'embed des règles
            embed = discord.Embed(
                title=f"📜 Règlement de {interaction.guild.name}",
                description=self.rules_content.value,
                color=EMBED_COLOR
            )
            
            embed.set_footer(text=f"Dernière mise à jour: {datetime.now().strftime('%d/%m/%Y')}")
            
            if interaction.guild.icon:
                embed.set_thumbnail(url=interaction.guild.icon.url)
            
            # Enregistrer les règles dans la base de données
            set_rules(interaction.guild.id, self.rules_content.value, interaction.user.id)
            
            # Envoyer l'embed
            await interaction.channel.send(embed=embed)
            
            await log_action(
                interaction.guild, 
                interaction.user, 
                interaction.user, 
                "Création des règles", 
                f"Règles créées dans le salon {interaction.channel.name}"
            )
            
            await interaction.response.send_message("Les règles ont été créées avec succès.", ephemeral=True)
    
    await interaction.response.send_modal(RulesModal())

@bot.tree.command(name="sos", description="Envoie une alerte SOS à l'équipe de HypeProtect")
async def sos(interaction: discord.Interaction):
    # Récupérer le salon de logs
    guild_id = interaction.guild.id
    config = get_server_config(guild_id)
    
    if not config or not config['logs_channel_id']:
        await interaction.response.send_message("Le système d'alerte SOS n'est pas configuré. Contactez un administrateur.", ephemeral=True)
        return
    
    logs_channel = interaction.guild.get_channel(config['logs_channel_id'])
    if not logs_channel:
        await interaction.response.send_message("Le salon de logs n'a pas été trouvé. Contactez un administrateur.", ephemeral=True)
        return
    
    # Envoyer un modal pour saisir la raison
    class SOSModal(discord.ui.Modal, title="Alerte SOS"):
        reason = discord.ui.TextInput(
            label="Raison de l'alerte",
            style=discord.TextStyle.paragraph,
            placeholder="Expliquez pourquoi vous avez besoin d'aide urgente...",
            required=True,
            max_length=1000
        )
        
        async def on_submit(self, interaction: discord.Interaction):
            # Mentionner tous les modérateurs
            mod_roles = [role for role in interaction.guild.roles if role.permissions.kick_members or role.permissions.ban_members]
            
            mentions = []
            for role in mod_roles:
                mentions.append(role.mention)
            
            if not mentions:
                mentions = ["@here"]
            
            mentions_text = " ".join(mentions)
            
            # Créer l'embed d'alerte
            embed = discord.Embed(
                title="🚨 ALERTE SOS 🚨",
                description=f"Une alerte d'urgence a été déclenchée par {interaction.user.mention}!",
                color=0xFF0000
            )
            
            embed.add_field(name="Utilisateur", value=f"{interaction.user.mention} ({interaction.user.name})", inline=True)
            embed.add_field(name="Salon", value=interaction.channel.mention, inline=True)
            embed.add_field(name="Raison", value=self.reason.value, inline=False)
            
            if interaction.user.avatar:
                embed.set_thumbnail(url=interaction.user.avatar.url)
            
            embed.set_footer(text=f"ID d'alerte: {random.randint(100000, 999999)} | {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            
            # Envoyer l'alerte
            await logs_channel.send(content=mentions_text, embed=embed)
            
            await log_action(
                interaction.guild, 
                interaction.user, 
                interaction.user, 
                "Alerte SOS", 
                self.reason.value
            )
            
            # Confirmer à l'utilisateur
            await interaction.response.send_message("Votre alerte SOS a été envoyée à l'équipe de modération. Ils interviendront rapidement.", ephemeral=True)
    
    await interaction.response.send_modal(SOSModal())

@bot.tree.command(name="unlock", description="Débloque l'accès à l'écriture dans un salon")
@app_commands.describe(role="Le rôle à déverrouiller (facultatif)")
async def unlock(interaction: discord.Interaction, role: Optional[discord.Role] = None):
    if not has_permission(interaction, "mod"):
        await interaction.response.send_message("Vous n'avez pas les permissions nécessaires pour utiliser cette commande.", ephemeral=True)
        return
    
    channel = interaction.channel
    
    if role:
        # Déverrouiller pour un rôle spécifique
        overwrite = channel.overwrites_for(role)
        overwrite.send_messages = None
        await channel.set_permissions(role, overwrite=overwrite)
        
        embed = discord.Embed(
            title="Salon déverrouillé",
            description=f"Le salon {channel.mention} a été déverrouillé pour le rôle {role.mention}.",
            color=SUCCESS_COLOR
        )
        
        await log_action(
            interaction.guild, 
            interaction.user, 
            interaction.user, 
            "Unlock", 
            f"Salon {channel.name} déverrouillé pour le rôle {role.name}"
        )
    else:
        # Déverrouiller pour @everyone
        everyone = interaction.guild.default_role
        overwrite = channel.overwrites_for(everyone)
        overwrite.send_messages = None
        await channel.set_permissions(everyone, overwrite=overwrite)
        
        embed = discord.Embed(
            title="Salon déverrouillé",
            description=f"Le salon {channel.mention} a été déverrouillé pour tout le monde.",
            color=SUCCESS_COLOR
        )
        
        await log_action(
            interaction.guild, 
            interaction.user, 
            interaction.user, 
            "Unlock", 
            f"Salon {channel.name} déverrouillé pour tout le monde"
        )
    
    await interaction.response.send_message(embed=embed)

# Lancement du bot (remplacer avec votre propre token)
bot.run('NzYxOTEyMDg5NzU3MzUxOTU2.G4XSoB.x0fMmN07K3Qb__QOojBcvyde_T5xPZyuL65ZMo')
