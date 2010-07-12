#! /usr/bin/ruby

#--
# Copyright (c) 2004, Guillaume Marcais (guillaume.marcais@free.fr)
# All rights reserved.
# This file is distributed under the Ruby license.
# http://net-tftp.rubyforge.org
#++
#
# == Description
# TFTP is used by many devices to upload or download their configuration,
# firmware or else. It is a very simple file transfer protocol built on top
# of UDP. It transmits data by chunck of 512 bytes. It waits for an ack after 
# each data packet but does not do any data integrety checks. 
# There is no authentication mechanism nor any way too list the content of 
# the remote directories. It just sends or retrieves files.
#
# == Usage
# Using Net::TFTP::Client is fairly trivial:
# <pre>
# <code>
# require 'net/tftp'
# t = Net::TFTP::Client.new('localhost')
# t.getbinaryfile('remote_file', 'local_file')
# t.putbinaryfile('local_file', 'remote_file')
# </code>
# </pre>
#
# To use the Net::TFTP::Server:
# <pre>
# <code>
# require 'net/tftp'
# tftp_server = Net::TFTP::Server.new(:data_directory => "/path/to/directory")
# tftp_server.start  # starts the server and blocks the current thread.
# </code>
# </pre>
# That's pretty much it. +getbinaryfile+ and +putbinaryfile+ can take a
# block which will be called every time a block is sent/received.
#
# == Known limitations
# * RFC 1350 mention a net-ascii mode. I am not quite sure what transformation
#   on the data should be done and it is not (yet) implemented.
# * None of the extensions of TFTP are implemented (RFC1782, RFC1783, RFC1784, 
#   RFC1785, RFC2347, RFC2348, RFC2349).
 
require 'socket'
require 'timeout'
require 'thread'

module Net # :nodoc:

  module TFTP # :nodoc:
    
  class TFTPError < StandardError; end
  class TFTPTimeout < TFTPError; end
  class TFTPProtocol < TFTPError
    attr_reader :code
    def initialize(msg, code)
      super(msg)
      @code = code
    end
  end

  VERSION = "0.2.0"

  # Errors
  ERROR_DESCRIPTION = [
    "Custom error",
    "File not found",
    "Access violation",
    "Disk full",
    "Illegal TFTP operation",
    "Unknown transfer ID",
    "File already exists",
    "No such user",
  ]
  ERROR_UNDEF                 = 0
  ERROR_FILE_NOT_FOUND        = 1
  ERROR_ACCESS_VIOLATION      = 2
  ERROR_DISK_FULL             = 3
  ERROR_ILLEGAL_OPERATION     = 4
  ERROR_UNKNOWN_TRANSFER_ID   = 5
  ERROR_FILE_ALREADY_EXISTS   = 6
  ERROR_NO_SUCH_USER          = 7
  
  # Opcodes
  OP_RRQ   = 1
  OP_WRQ   = 2
  OP_DATA  = 3
  OP_ACK   = 4
  OP_ERROR = 5
  
  MINSIZE = 4
  MAXSIZE = 516
  DATABLOCK = 512
  
  DEFAULTS = {
    :port => (Socket.getservbyname("tftp", "udp") rescue 69),
    :timeout => 5,
  }

  module PacketOperations
    def rrq_packet(file, mode)
      [OP_RRQ, file, mode].pack("na#{file.size + 1}a#{mode.size + 1}")
    end

    def wrq_packet(file, mode)
      [OP_WRQ, file, mode].pack("na#{file.size + 1}a#{mode.size + 1}")
    end

    def data_packet(block, data)
      [OP_DATA, block, data].pack("nna*")
    end

    def ack_packet(block)
      [OP_ACK, block].pack("nn")
    end

    def error_packet(code, message = nil)
      message ||= ERROR_DESCRIPTION[code] || ""
      [OP_ERROR, code, message].pack("nna#{message.size + 1}")
    end

    # Check if the packet is malformed (unknown opcode, too big, etc.),
    # in which case it returns nil.
    # If it is an error packet, raise an TFTPProtocol error.
    # Returns scanned values otherwise.
    def scan_packet(packet)
      return nil if packet.size < MINSIZE || packet.size > MAXSIZE
      opcode = packet.unpack("n")[0]
      block_err = rest = nil
      if opcode == OP_RRQ || opcode == OP_WRQ
        block_err, rest = packet[2..-1].unpack("Z*Z*")
      elsif opcode == OP_ERROR
        block_err, rest = packet[2..-1].unpack("nZ*")
      else
        block_err = packet[2..-1].unpack("n")[0]
        rest = packet[4..-1]
      end
      return nil if opcode.nil? || block_err.nil?
      case opcode
      when OP_RRQ, OP_WRQ
        return [opcode, block_err, rest]
      when OP_DATA
        return [opcode, block_err, rest]
      when OP_ACK
        return [opcode, block_err]
      when OP_ERROR
        err_msg = "%s: %s"
        err_msg %= [ERROR_DESCRIPTION[block_err] || "", rest.chomp("\000")]
        raise TFTPProtocol.new(err_msg, block_err)
      else
        return nil
      end
    end
  end #module PacketOperations
  
  class Client
    include PacketOperations
    class << self
      # Alias for new
      def open(host)
        new(host)
      end

      # Return the number of blocks to send _size_ bytes.
      def size_in_blocks(size)
        s = size / DATABLOCK
        s += 1 unless (size % DATABLOCK) == 0
        s
      end
    end
    
    attr_accessor :timeout, :host

    # Create a TFTP connection object to a host. Note that no actual
    # network connection is made. This methods never fails.
    # Parameters:
    # [:port] The UDP port. See DEFAULTS
    # [:timeout] Timeout in second for each ack packet. See DEFAULTS
    def initialize(host, params = {})
      @host = host
      @port = params[:port] || DEFAULTS[:port]
      @timeout = params[:timeout] || DEFAULTS[:timeout]
    end

    # Retrieve a file using binary mode.
    # If the localfile name is omitted, it is set to the remotefile.
    # The optional block receives the data in the block and the sequence number
    # of the block starting at 1.
    def getbinaryfile(remotefile, localfile = nil, &block) # :yields: data, seq
      localfile ||= File.basename(remotefile)
      open(localfile, "wb") do |f|
        getbinary(remotefile, f, &block)
      end
    end

    # Retrieve a file using binary mode and send content to an io object
    # The optional block receives the data in the block and the sequence number
    # of the block starting at 1.
    def getbinary(remotefile, io, &block) # :yields: data, seq
      s = UDPSocket.new
      begin
        peer_ip = IPSocket.getaddress(@host)
      rescue
        raise TFTPError, "Cannot find host '#{@host}'"
      end

      peer_tid = nil
      seq = 1
      from = nil
      data = nil

      # Initialize request
      s.send(rrq_packet(remotefile, "octet"), 0, peer_ip, @port)
      Timeout::timeout(@timeout, TFTPTimeout) do
        loop do
          packet, from = s.recvfrom(MAXSIZE, 0)
          next unless peer_ip == from[3]
          type, block, data = scan_packet(packet)
          break if (type == OP_DATA) && (block == seq)
        end
      end
      peer_tid = from[1]

      # Get and write data to io
      loop do
        io.write(data)
        s.send(ack_packet(seq), 0, peer_ip, peer_tid)
        yield(data, seq) if block_given?
        break if data.size < DATABLOCK
        
        seq += 1
        Timeout::timeout(@timeout, TFTPTimeout) do
          loop do
            packet, from = s.recvfrom(MAXSIZE, 0)
            next unless peer_ip == from[3]
            if peer_tid != from[1]
              s.send(error_packet(ERROR_UNKNOWN_TRANSFER_ID), 
                     0, from[3], from[1])
              next
            end
            type, block, data = scan_packet(packet)
            break if (type == OP_DATA) && (block == seq)
          end
        end
      end

      return true
    end

    # Send a file in binary mode. The name of the remotefile is set to
    # the name of the local file if omitted.
    # The optional block receives the data in the block and the sequence number
    # of the block starting at 1.
    def putbinaryfile(localfile, remotefile = nil, &block) # :yields: data, seq
      remotefile ||= File.basename(localfile)
      open(localfile, "rb") do |f|
        putbinary(remotefile, f, &block)
      end
    end

    # Send the content read from io to the remotefile.
    # The optional block receives the data in the block and the sequence number
    # of the block starting at 1.
    def putbinary(remotefile, io, &block) # :yields: data, seq
      s = UDPSocket.new
      peer_ip = IPSocket.getaddress(@host)
      
      peer_tid = nil
      seq = 0
      from = nil
      data = nil
      
      # Initialize request
      s.send(wrq_packet(remotefile, "octet"), 0, peer_ip, @port)
      Timeout::timeout(@timeout, TFTPTimeout) do
        loop do
          packet, from = s.recvfrom(MAXSIZE, 0)
          next unless peer_ip == from[3]
          type, block, data = scan_packet(packet)
          break if (type == OP_ACK) && (block == seq)
        end
      end
      peer_tid = from[1]

      loop do
        data = io.read(DATABLOCK) || ""
        seq += 1
        s.send(data_packet(seq, data), 0, peer_ip, peer_tid)
        
        Timeout::timeout(@timeout, TFTPTimeout) do
          loop do
            packet, from = s.recvfrom(MAXSIZE, 0)
            next unless peer_ip == from[3]
            if peer_tid != from[1]
              s.send(error_packet(ERROR_UNKNOWN_TRANSFER_ID), 
                     0, from[3], from[1])
              next
            end
            type, block, void = scan_packet(packet)
            break if (type == OP_ACK) && (block == seq)
          end
        end

        yield(data, seq) if block_given?
        break if data.size < DATABLOCK
      end
      
      return true
    end

  end #TFTP
  
  # Simple factory for returning RRQ and WRQ source/sinks.
  class DefaultOpFactory
    # Returns a handler for a 'get' file.  Throw a TFTPError if the
    # resource is not allowed.
    def rrq_operation_for(file_name, remote_host)
      RRQOperation.new(file_name)
    end
    
    # Returns the handler for 'put' file.  Throw a TFTPError if the
    # resource is not allowed.
    def wrq_operation_for(file_name, remote_host)
      WRQOperation.new(file_name)
    end
  end
  
  class Server
	  attr_accessor :options
	  include PacketOperations
	  
	  # options: port, timeout, max_threads, data_directory, operation_factory
	  def initialize(options = { :port => 69, :timeout => 5, :max_threads => 10 })
	    @socket = UDPSocket.open
	    @options = options.clone
	    @op_factory = @options[:operation_factory] || DefaultOpFactory.new
	    @options[:port] ||= DEFAULTS[:port]
	    @options[:max_pkt_size] ||= 8000
	    @options[:timeout] ||= DEFAULTS[:timeout]
      @socket.bind("0.0.0.0", @options[:port])
      @worker_threads = []
      @queue = [] # queue of [data, remote_addr]
      @mutex = Mutex.new
      @condition_var = ConditionVariable.new
      # Hash of IP:Port => TFTPOperation
      @operations = {}
    end
    
    def start
      # Create worker threads
      (@options[:max_threads] || 2).times do |i|
        @worker_threads << Thread.new(self) do |server|
          loop do
            begin
              server.dequeue_and_process
            rescue Exception => e
              puts e
              puts e.backtrace.join("\n")
            end
          end
        end
      end

      Thread.new(self) do |server|
        loop do
          sleep 6
          begin
            server.remove_expired_operations
          rescue Exception => e
            puts e
            puts e.backtrace.join("\n")
          end
        end
      end
      
      loop do
        begin
          data, remote_info = @socket.recvfrom(@options[:max_pkt_size])
          dispatch(data, remote_info)
        rescue Exception => e
          puts "TFTP::Server exception: #{e}\n#{e.backtrace.join('\n')}"
          break
        end
      end
    end

    def stop
      @worker_threads.each { |thread| thread.kill }
      @worker_threads.clear
      @socket.close
    end

    def send_reply(block, remote_info)
      # socket ops are 'thread' safe
      @socket.send(block, 0, remote_info[3], remote_info[1])
    end
    
    def dispatch(data, remote_info)
      @mutex.synchronize do
        @queue << [data, remote_info]
        @condition_var.signal
      end
    end
    
    def work_unit
      unit = nil
      @mutex.synchronize do
        loop do
          unit = @queue.pop
          break unless unit.nil?
          @condition_var.wait(@mutex)
        end
      end
      unit
    end

    def dequeue_and_process
      data, remote_info = work_unit
      scan = scan_packet(data) # operation, ([file_name, xfer type] || [block_num, data])

      case scan[0]
      when OP_WRQ
        begin
          add_operation(@op_factory.wrq_operation_for(full_path(scan[1]), remote_info), remote_info)
          send_reply(ack_packet(0), remote_info)
        rescue Exception => e
          puts "*ERROR* #{e}\n#{e.backtrace.join('\n')}"
          error_code = ERROR_ACCESS_VIOLATION
          error_code = e.code if e.is_a?(TFTPProtocol)
          send_reply(error_packet(error_code), remote_info)
        end

      when OP_RRQ
        begin
          rrq_op = add_operation(@op_factory.rrq_operation_for(full_path(scan[1]), remote_info), remote_info)
          send_reply(data_packet(*rrq_op.data_block), remote_info)
        rescue TFTPError => e
          error_code = ERROR_ACCESS_VIOLATION
          error_code = e.code if e.is_a?(TFTPProtocol)
          send_reply(error_packet(error_code), remote_info)
        end

      when OP_DATA
        op = operation_for(remote_info)
        if op && op.is_a?(WRQOperation)
          begin
            bytes = op.incoming_data(scan[2], scan[1])
            if bytes < 512
              op.complete
              # We don't remove the operation incase the client loses the last ack.
              # We'll let the expiring wrapper remove it.
              #remove_operation_for(remote_info)  
            end
            # We'll always ACK the given packet number since it could be a retry.
            send_reply(ack_packet(scan[1]), remote_info)
          rescue Exception => e
            puts "OP_DATA ERROR: #{e}\n#{e.backtrace.join("\n")}"
          end
        else
          send_reply(error_packet(ERROR_UNKNOWN_TRANSFER_ID), remote_info)
        end

      when OP_ACK
        op = operation_for(remote_info)
        if op && op.is_a?(RRQOperation)
          send_reply(data_packet(*op.data_block), remote_info)
        else
          send_reply(error_packet(ERROR_UNKNOWN_TRANSFER_ID), remote_info)
        end
      else
        send_reply(error_packet(ERROR_UNKNOWN_TRANSFER_ID), remote_info)
      end
    end
    
    def remote_key(remote_info)
      "#{remote_info[3]}:#{remote_info[1]}"
    end
    
    def add_operation(op, remote_info)
      @mutex.synchronize do
        # Double the timeout value for the auto-expiring to allow for retry operations
        @operations[remote_key(remote_info)] = ExpiringWrapper.new(op, @options[:timeout] * 2)
      end
      op
    end
    
    # Checks for an existing connection/operation for the given
    # IP/port
    def operation_for(remote_info)
      @mutex.synchronize do
        exp_wrapper = @operations[remote_key(remote_info)]
        exp_wrapper.operation if exp_wrapper
      end
    end
    
    def remove_operation_for(remote_info)
      @mutex.synchronize do
        @operations.delete(remote_key(remote_info))
      end
    end
    
    # Removes operations/connections that haven't had any activity recently
    def remove_expired_operations
      @mutex.synchronize do
        @operations.delete_if { |k,wop| wop.operation.abort if wop.expired? ; wop.expired? }
      end
    end
    
    private
    def full_path(file_name)
      # do some cleanup to prevent unwanted directory traversal
      file_name = file_name.gsub("..", "").gsub(/^[\/\\]*/, "")
      result = file_name
      if @options[:data_directory]
        result = "#{File.join(File.expand_path(@options[:data_directory]), file_name)}"
      end
      result
    end
    
	end #TFTP::Server

  # Base class for GET/PUT
  class TFTPOperation
    attr_reader :file_name
  
    def initialize(file_name)
      @file_name = file_name
      @fp = File.new(file_name, file_mode)
      @complete = false
      @aborted = false
    end
  
    def complete
      unless @complete
        @fp.close unless @fp.closed?
        @complete = true
      end
    end
  
    def complete?
      @complete
    end
  
    def aborted?
      @aborted
    end
  
    def abort
      return false if complete? # Can't abort a completed operation.
      @fp.close unless @fp.closed?
      @aborted = true
    end
  end

  # PUT
  class WRQOperation < TFTPOperation
    def initialize(file_name, fmode = "wb")
      raise TFTPProtocol.new("File exists", ERROR_FILE_ALREADY_EXISTS) if File.exist?(file_name)
      @file_mode = fmode
      @last_block_num = 0
      super file_name
    end
  
    def incoming_data(data, block_num)
      # Ignore writes if we're complete.  This case can occur if the final ACK was lost
      if block_num == @last_block_num + 1
        @fp.write(data) unless complete?
        @last_block_num = block_num
      elsif block_num == @last_block_num   # Didn't get last ack.
        puts "Client lost ACK.  Ignoring resend." if $debug
      else
        # We got a block number that we shouldn't have
        raise TFTPProtocol.new("Unexpected block number #{block_num}.  Expected #{@last_block_num + 1}.", ERROR_ILLEGAL_OPERATION)
      end
      data.size
    end
  
    def file_mode
      @file_mode
    end
  
    def aborted
      super
      File.delete(@fp.path) unless complete?
    end
  end

  # GET
  # TODO: Handle retry/file repos logic
  class RRQOperation < TFTPOperation
    def initialize(file_name)
      begin
        super
      rescue Errno::ENOENT => e
        raise TFTPProtocol.new(e.message, ERROR_FILE_NOT_FOUND)
      end
      @block_num = 0
    end
  
    def data_block(max_size = 512)
      [@block_num += 1, @fp.read(max_size)]
    end
  
    def file_mode
      "rb"
    end
  end

  # Simple wrapper that tracks last access time to allow for
  # expiring of entries.  TTL is in seconds.
  class ExpiringWrapper
    def initialize(operation, time_to_live = 10)
      @operation = operation
      @last_access = Time.now
      @time_to_live = time_to_live
    end
  
    def operation
      @last_access = Time.now
      @operation
    end
  
    def expired?
      Time.now - @last_access >= @time_to_live
    end
  end

  end #TFTP module
end #Net module
