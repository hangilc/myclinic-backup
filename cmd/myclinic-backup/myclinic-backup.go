package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	cflib "github.com/hangilc/crypt-file/lib"
)

const (
	mysqlUserEnvVar          = "MYCLINIC_DB_USER"
	mysqlPassEnvVar          = "MYCLINIC_DB_PASS"
	backupDirEnvVar          = "MYCLINIC_BACKUP_DIR"
	encryptedBackupDirEnvVar = "MYCLINIC_BACKUP_ENCRYPTED_DIR"
	encryptionKey            = "MYCLINIC_BACKUP_ENCRYPTION_KEY"
	s3BackupRegionEnvVar     = "MYCLINIC_BACKUP_S3_REGION"
	s3BackupBucketEnvVar     = "MYCLINIC_BACKUP_S3_BUCKET"
)

func printEnvReference() {
	fmt.Print(`
MYCLINIC_DB_USER -- database user
MYCLINIC_DB_PASS -- database password
MYCLINIC_BACKUP_DIR -- directory to store plain SQL backup file
MYCLINIC_BACKUP_ENCRYPTED_DIR -- directory to store encrypted SQL backup file
MYCLINIC_BACKUP_ENCRYPTION_KEY -- path to encryption key file
MYCLINIC_BACKUP_S3_REGION -- S3 region
MYCLINIC_BACKUP_S3_BUCKET -- S3 bucket
`)
}

var dryRun = flag.Bool("dry-run", false, "does not actually run commands")
var printEnv = flag.Bool("env", false, "prints relevant env vars")

func uploadToS3(region string, bucket string, key string, filename string) error {
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	uploader := s3manager.NewUploader(sess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   file,
	})
	return err
}

func getenv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fmt.Fprintf(os.Stderr, "cannot get env var %s", name)
		os.Exit(1)
	}
	return value
}

func dirPart(dateTime time.Time) string {
	return dateTime.Format("2006-01")
}

func filePart(dateTime time.Time) string {
	return "dump-" + dateTime.Format("200601021504") + ".sql"
}

func encryptedBackupResult(src string) string {
	reg := regexp.MustCompile(`(.+)(\.(\w+))$`)
	return reg.ReplaceAllString(src, "$1-$3.cf")
}

func createBackupFilePath(dir string, dateTime time.Time) string {
	p := dir + "/" + dirPart(dateTime) + "/" + filePart(dateTime)
	p = filepath.ToSlash(p)
	return filepath.Clean(p)
}

func dumpMysql(backupFile string) error {
	dir := filepath.Dir(backupFile)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}
	user := getenv(mysqlUserEnvVar)
	pass := getenv(mysqlPassEnvVar)
	cmd := exec.Command("mysqldump", "-u", user, "-p"+pass,
		"--default-character-set=utf8", "myclinic", "--result-file="+backupFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return err
	}
	exitCode := cmd.ProcessState.ExitCode()
	if exitCode != 0 {
		return fmt.Errorf("mysqldump failed with exit code: %d", exitCode)
	}
	return nil
}

func copyFile(dst, src string) (int64, error) {
	fin, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer fin.Close()
	fout, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer fout.Close()
	return io.Copy(fout, fin)
}

func invokeAxCrypt(prog string, password string, src string) error {
	cmd := exec.Command(prog, "-b", "2", "-e", "-k", password, "-z", src)
	err := cmd.Run()
	if err != nil {
		return err
	}
	exitCode := cmd.ProcessState.ExitCode()
	if exitCode != 0 {
		return fmt.Errorf("axcrypt failed with exit code %d", exitCode)
	}
	return nil
}

func encryptBackupFile(dstPath string, key []byte, srcPath string) error {
	fmt.Printf("dstPath %s\n", dstPath)
	dir := filepath.Dir(dstPath)
	fmt.Printf("dst dir %s\n", dir)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}
	in, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return err
	}
	enc, err := cflib.CompressAndEncrypt(key, in)
	err = ioutil.WriteFile(dstPath, enc, 0600)
	return nil
}

func createS3Key(encryptedFile string) string {
	dir, base := filepath.Split(encryptedFile)
	_, dirbase := filepath.Split(filepath.Clean(dir + "."))
	return dirbase + "/" + base
}

func getEncryptionKey() ([]byte, error) {
	keyPath := os.Getenv(encryptionKey)
	if keyPath == "" {
		return nil, fmt.Errorf("Cannot get key path from $%s", encryptionKey)
	}
	return cflib.ReadKeyFile(keyPath)
}

func main() {
	flag.Parse()
	if *printEnv {
		printEnvReference()
		return
	}
	now := time.Now()
	backupDir := getenv(backupDirEnvVar)
	backupFile := createBackupFilePath(backupDir, now)
	if !*dryRun {
		err := dumpMysql(backupFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mysql backup failed: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("database backed up to %s\n", backupFile)
	encryptedBackupDir := getenv(encryptedBackupDirEnvVar)
	encSrc := createBackupFilePath(encryptedBackupDir, now)
	encryptedFile := encryptedBackupResult(encSrc)
	if !*dryRun {
		key, err := getEncryptionKey()
		if err != nil {
			panic(err)
		}
		err = encryptBackupFile(encryptedFile, key, backupFile)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("encrypted file: %s\n", encryptedFile)
	region := getenv(s3BackupRegionEnvVar)
	fmt.Printf("region: %s\n", region)
	bucket := getenv(s3BackupBucketEnvVar)
	key := createS3Key(encryptedFile)
	fmt.Printf("S3 key: %s\n", key)
	if !*dryRun {
		err := uploadToS3(region, bucket, key, encryptedFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to upload to S3: %v\n", err)
			os.Exit(1)
		}
	}
}
