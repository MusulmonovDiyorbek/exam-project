import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req, ParseIntPipe } from '@nestjs/common';
import { Request } from 'express';
import { AssignmentService } from './assignment.service';
import { CreateAssignmentDto } from './dto/create-assignment.dto';
import { UpdateAssignmentDto } from './dto/update-assignment.dto';
import { JwtAuthGuard } from 'src/auth/guard/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guard/roles.guard';
import { Roles } from 'src/auth/decorators/role.decorator';
import { User } from 'src/users/entities/user.entity';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('assignment')
export class AssignmentController {
  constructor(private readonly assignmentService: AssignmentService) { }
  @Post()
  @Roles('student') 
    create(@Body() createAssignmentDto: CreateAssignmentDto, @Req() req: Request) {
      const student = req.user as any;
      console.log(student);
      
      return this.assignmentService.create(student, createAssignmentDto);
    }
  
  @Get('/model/:modelId')
  // @Roles('teacher', 'admin')
  findByModel(@Param('modelId', ParseIntPipe) modelId: number) {
    return this.assignmentService.findByModel(modelId); 
  }
  
  @Get(':id') 
  // @Roles('teacher', 'admin', 'student')
  findOne(@Param('id') id: string) {
    return this.assignmentService.findOneById(+id);
  }

  @Patch(':id')
  // @Roles('student')
  update(@Param('id') id: string, @Body() updateAssignmentDto: UpdateAssignmentDto) {
    return this.assignmentService.update(+id, updateAssignmentDto);
  }
  
  @Delete(':id')
  // @Roles('student', 'admin')
  remove(@Param('id') id: string) {
    return this.assignmentService.remove(+id);
  }
}