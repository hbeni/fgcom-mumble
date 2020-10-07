<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<project default="all" name="jmapviewer" xmlns:jacoco="antlib:org.jacoco.ant" xmlns:if="ant:if" xmlns:unless="ant:unless">

    <property name="java.lang.version" value="1.8" />
    <dirname property="base.dir" file="${ant.file.jmapviewer}"/>
    <property name="tools.dir" location="${base.dir}/tools"/>
    <property name="jacoco.includes" value="org.openstreetmap.gui.jmapviewer.*" />
    <property name="jacoco.inclbootstrapclasses" value="false" />
    <property name="jacoco.inclnolocationclasses" value="false" />
    <!-- For Java specific stuff by version -->
    <condition property="isJava9"><matches string="${ant.java.version}" pattern="(1.)?(9|1[0-9])" /></condition>
    <condition property="isJava10"><matches string="${ant.java.version}" pattern="1[0-9]" /></condition>
    <condition property="isJava11"><matches string="${ant.java.version}" pattern="1[1-9]" /></condition>
    <condition property="isJava12"><matches string="${ant.java.version}" pattern="1[2-9]" /></condition>
    <condition property="isJava13"><matches string="${ant.java.version}" pattern="1[3-9]" /></condition>
    <!-- Disable jacoco on Java 13+, see https://github.com/jacoco/jacoco/pull/738 -->
    <condition property="coverageByDefault">
        <not>
            <isset property="isJava13"/>
        </not>
    </condition>
    <path id="test.classpath">
        <fileset dir="${tools.dir}/testlib">
            <include name="**/*.jar"/>
        </fileset>
        <pathelement location="bin"/>
    </path>

    <target name="all" depends="clean,build,test,svn_info,pack,create_run_jar,spotbugs,checkstyle,javadoc,create_release_zip,create_source_release_zip" />

    <target name="clean">
        <mkdir dir="bin" />
        <mkdir dir="bintest" />
        <mkdir dir="javadoc" />
        <mkdir dir="report" />
        <delete>
            <fileset dir="bin">
                <include name="**" />
            </fileset>
            <fileset dir="bintest">
                <include name="**" />
            </fileset>
            <fileset dir="javadoc">
                <include name="**" />
            </fileset>
            <fileset dir="report">
                <include name="**" />
            </fileset>
            <fileset dir="." includes="*.jar,*.exec"/>
        </delete>
    </target>

    <target name="build" depends="clean">
        <javac srcdir="src" destdir="bin" source="${java.lang.version}" target="${java.lang.version}" debug="true" includeantruntime="false" encoding="UTF-8">
            <include name="org/openstreetmap/gui/jmapviewer/**" />
        </javac>

        <copy todir="bin">
            <fileset dir="src">
                <include name="**/*.png" />
            </fileset>
        </copy>
    </target>

    <target name="svn_info" description="Get SVN info for use in JAR/ZIP filenames.">
        <!-- Get the svn ReleaseVersion property -->
        <exec executable="svn" outputproperty="svnReleaseVersion">
            <arg line="propget ReleaseVersion" />
            <env key="LANG" value="en_US"/>
        </exec>
    </target>
    
    <target name="pack" depends="build">
        <!-- Create the JAR file containing the compiled class files -->
        <jar destfile="JMapViewer.jar" filesetmanifest="mergewithoutmain">
            <fileset dir="bin" includes="**/jmapviewer/**" />
        </jar>
        <!-- Create the JAR file containing the source java files -->
        <jar destfile="JMapViewer_src.jar" filesetmanifest="mergewithoutmain">
            <fileset dir="src" includes="**/jmapviewer/**" />
        </jar>
    </target>
    
    <!-- if you want to build outside of svn, use "ant clean build [pack]" -->
    
    <target name="create_run_jar" description="Create a JAR file that can be used to execute the JMapViewer demo app. Requires JMapViewer.jar to be present.">
        <jar destfile="JMapViewer_Demo.jar" filesetmanifest="mergewithoutmain">
            <manifest>
                <attribute name="Main-Class" value="org.openstreetmap.gui.jmapviewer.Demo" />
                <attribute name="Class-Path" value="JMapViewer.jar" />
            </manifest>
        </jar>
    </target>

    <target name="create_release_zip" description="Create a release zip file containing the binary and source jar files as well as the demo starter">
        <zip basedir="." destfile="releases/${svnReleaseVersion}/JMapViewer-${svnReleaseVersion}.zip">
            <include name="JMapViewer*.jar" />
            <include name="Readme.txt" />
            <include name="Gpl.txt" />
        </zip>
        <delete>
            <fileset dir="." includes="JMapViewer*.jar"/>
        </delete> 
    </target>
    
    <target name="create_source_release_zip" description="Create a release zip file containing the source files">
        <zip destfile="releases/${svnReleaseVersion}/JMapViewer-${svnReleaseVersion}-Source.zip">
            <zipfileset file="Readme.txt" prefix="jmapviewer-${svnReleaseVersion}"/>
            <zipfileset file="build.xml" prefix="jmapviewer-${svnReleaseVersion}"/>
            <zipfileset file="Gpl.txt" prefix="jmapviewer-${svnReleaseVersion}"/>
            <zipfileset dir="src" includes="**/jmapviewer/**" prefix="jmapviewer-${svnReleaseVersion}/src"/>
        </zip>
    </target>

    <target name="checkstyle">
        <taskdef resource="com/puppycrawl/tools/checkstyle/ant/checkstyle-ant-task.properties" 
            classpath="tools/checkstyle/checkstyle-all.jar"/>
        <checkstyle config="tools/checkstyle/jmapviewer_checks.xml">
            <fileset dir="${basedir}/src" includes="**/*.java" />
            <formatter type="xml" toFile="checkstyle-jmapviewer.xml"/>
        </checkstyle>
    </target>

    <target name="spotbugs" depends="pack">
        <taskdef name="spotbugs" classname="edu.umd.cs.findbugs.anttask.FindBugsTask" 
            classpath="tools/spotbugs/spotbugs-ant.jar"/>
        <path id="spotbugs-classpath">
            <fileset dir="tools/spotbugs/">
                <include name="*.jar"/>
            </fileset>
        </path>
        <property name="spotbugs-classpath" refid="spotbugs-classpath"/>
        <spotbugs output="xml"
                outputFile="spotbugs-jmapviewer.xml"
                classpath="${spotbugs-classpath}"
                effort="max"
                >
            <sourcePath path="${basedir}/src" />
            <class location="JMapViewer.jar" />
        </spotbugs>
    </target>

    <target name="javadoc">
        <javadoc destdir="javadoc" 
                sourcepath="src"
                encoding="UTF-8"    
                packagenames="org.openstreetmap.gui.jmapviewer.*"
                windowtitle="JMapViewer"
                use="true"
                private="true"
                linksource="true"
                author="false">
            <link href="https://docs.oracle.com/javase/8/docs/api"/>
            <doctitle><![CDATA[<h2>JMapViewer - Javadoc</h2>]]></doctitle>
            <bottom><![CDATA[<a href="https://josm.openstreetmap.de/">JMapViewer</a>]]></bottom>
            <arg value="-html5" if:set="isJava9" />
        </javadoc>
    </target>

    <target name="test" depends="clean, build">
        <taskdef uri="antlib:org.jacoco.ant" resource="org/jacoco/ant/antlib.xml" classpath="${tools.dir}/jacocoant.jar" />
        <javac srcdir="test" destdir="bintest"
            target="${java.lang.version}" source="${java.lang.version}" debug="on"
            includeantruntime="false" createMissingPackageInfoClass="false" encoding="UTF-8">
            <compilerarg value="-Xlint:all"/>
            <compilerarg value="-Xlint:-serial"/>
            <classpath>
            	<path refid="test.classpath"/>
            </classpath>
        </javac>
        <jacoco:coverage enabled="@{coverage}" includes="${jacoco.includes}"
            inclbootstrapclasses="${jacoco.inclbootstrapclasses}" inclnolocationclasses="${jacoco.inclnolocationclasses}">
            <junit printsummary="yes" fork="true" forkmode="once">
                <jvmarg value="-Dfile.encoding=UTF-8"/>
                <classpath>
                    <path refid="test.classpath"/>
                    <pathelement location="bintest"/>
                </classpath>
                <formatter type="plain"/>
                <formatter type="xml"/>
                <batchtest fork="yes" todir="report">
                    <fileset dir="bintest" includes="**/*Test.class"/>
                </batchtest>
            </junit>
        </jacoco:coverage>
    </target>

</project>
