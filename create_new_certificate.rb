#!/usr/bin/env ruby
$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'/lib'))

require 'rubygems'
require 'certificate_authority'
require 'json'
require 'time'

SECRET_KEYS_PATH = "./secrets/"
def key_exists?(key_name)
  raise ArgumentError, "Key #{key_name}.pem not found" if not File.exist? SECRET_KEYS_PATH + "#{key_name}.pem" \
  and File.exist? SECRET_KEYS_PATH + "#{key_name}.json" and File.exists? SECRET_KEYS_PATH + "#{key_name}.serial" 
  return key_name
end

def next_serial(key_name)
  begin
    current_serial = IO.read(SECRET_KEYS_PATH+"#{key_name}.serial").to_i
    File.open(SECRET_KEYS_PATH+"#{key_name}.serial", 'w') {|f| f.write(current_serial+1) }    
    return current_serial+1
  rescue Exception => message
    puts "Error: #{message}. Using serial 2. Current serial is in #{SECRET_KEYS_PATH}#{key_name}.serial}"
    return 2
  end
end

def create_signer_certificate (key_name, password)
  cert_params = JSON.parse(IO.read(SECRET_KEYS_PATH+"#{key_name}.json"))
  temp_cert = CertificateAuthority::Certificate.new()
  temp_cert.subject.common_name= cert_params["distinguished_name"]
  temp_cert.serial_number.number=cert_params["serial_number"]
  temp_cert.key_material.load_keys(SECRET_KEYS_PATH+"#{key_name}.pem", password)
  temp_cert.signing_entity = true
  temp_cert.extensions["crlDistributionPoints"].uri = "http://squareup.com/revoke.crl"
  temp_cert.not_before = Time.parse(cert_params["not_before"])
  temp_cert.not_after = Time.parse(cert_params["not_after"])
  temp_cert.sign!
  temp_cert
end

def generate_new_certificate (subject, parent, serial)
  temp_cert = CertificateAuthority::Certificate.new()
  temp_cert.subject.common_name= subject
  temp_cert.serial_number.number= serial
  temp_cert.key_material.generate_key 
  temp_cert.extensions["crlDistributionPoints"].uri = "http://squareup.com/revoke.crl"
  temp_cert.parent = parent
  temp_cert.sign!
  temp_cert
end

if __FILE__ == $0
  begin
    # puts "Please the key you wish to sign with (root, IT, etc):"
    # key_name = key_exists?(gets.gsub(/\n/,""))
    key_name = "root" # we only have one root certificate, for now
    key_exists? key_name
    puts "Please enter the certificate Common Name (CN):"
    subject = gets.gsub(/\n/,"")
    puts "Password for #{key_name} : " 
    password = gets.gsub(/\n/,"")
  rescue Exception => message
    puts "Error: #{message}"
  end
  parent = create_signer_certificate(key_name,password)
  next_serial_number = next_serial key_name
  new_cert = generate_new_certificate(subject,parent,next_serial_number)
  puts new_cert.to_pem
end