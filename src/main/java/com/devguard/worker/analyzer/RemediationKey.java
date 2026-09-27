package com.devguard.worker.analyzer;

import java.util.Locale;

/**
 * Identifica la ACCION que resuelve un hallazgo, no el hallazgo.
 *
 * Es la diferencia entre decirle al usuario que tiene once problemas y
 * decirle que tiene uno: once CVE de la misma biblioteca se cierran con una
 * sola linea en el pom.xml.
 *
 * Distincion importante frente al fingerprint. El fingerprint identifica un
 * hallazgo concreto para poder deduplicarlo entre scans; la clave de
 * remediacion identifica el arreglo, y a proposito es MENOS especifica para
 * que varios hallazgos la compartan.
 */
public class RemediationKey {

    private RemediationKey() {

    }

    public static String of(String analyzer, RawFinding f) {
        // Dependencias: el paquete. Todos sus CVE se cierran actualizandolo.
        // No se incluye la version instalada: si aparece un CVE nuevo del
        // mismo paquete, debe caer en el grupo existente.
        if ("DEPENDENCY".equals(f.category()) && notBlank(f.packageName())) {
            return "dependency:" + f.packageName().toLowerCase(Locale.ROOT);
        }

        // Secretos: el archivo. Varias credenciales en el mismo archivo se
        // atienden de una pasada, y la accion (sacarlas del repositorio y
        // rotarlas) es la misma.
        if ("SECRET".equals(f.category()) && notBlank(f.filePath())) {
            return "secret:" + f.filePath();
        }

        // Codigo y configuracion: regla mas archivo, sin la linea. La misma
        // regla incumplida veinte veces en un archivo es una sola revision.
        if (notBlank(f.ruleId()) && notBlank(f.filePath())) {
            return "code:" + f.ruleId() + ":" + f.filePath();
        }
        if (notBlank(f.ruleId())) {
            return "rule:" + f.ruleId();
        }

        // Sin datos para agrupar, el hallazgo es su propio grupo. Se usa el
        // fingerprint y no un aleatorio, o cada scan crearia un grupo nuevo.
        return "finding:" + f.fingerprint(analyzer);
    }


    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}