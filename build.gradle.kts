plugins {
    kotlin("jvm") version "2.1.0"
}

group = "moe.karla"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.apache.sshd:sshd-sftp:2.14.0")
    implementation("org.apache.sshd:sshd-netty:2.14.0")
    implementation("io.netty:netty-all:4.1.115.Final")
    implementation("ch.qos.logback:logback-classic:1.5.12")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation("net.i2p.crypto:eddsa:0.3.0")
    implementation("com.atlassian:onetime:2.1.1")

    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}